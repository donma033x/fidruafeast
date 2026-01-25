package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	statusFile    = "/tmp/fidrua.status"
	pidFile       = "/tmp/fidrua.pid"
	langFile      = "/tmp/fidrua.lang"
	chunkSize     = 10 * 1024 * 1024  // 10MB per memory chunk
	checkInterval = 2 * time.Second
)

// Language support
type Lang int

const (
	LangEN Lang = iota
	LangZH
)

var currentLang Lang = LangEN

// Text returns localized string
var texts = map[string][2]string{
	// General
	"select_lang":        {"Select language", "选择语言"},
	"invalid_option":     {"Invalid option", "无效选项"},
	"cancelled":          {"Cancelled", "已取消"},
	"confirm_yes":        {"y", "y"},
	"press_enter":        {"Press Enter to continue...", "按回车继续..."},
	
	// Main menu
	"main_menu":          {"Main Menu", "主菜单"},
	"opt_adopt":          {"Adopt Fidrua (install systemd service)", "领养 Fidrua (安装系统服务)"},
	"opt_background":     {"Run in background (temporary)", "临时后台运行"},
	"opt_foreground":     {"Run in foreground", "前台运行"},
	"opt_quit":           {"Quit", "退出"},
	"select_option":      {"Select option", "请选择"},
	
	// Service running menu
	"service_running":    {"Fidrua is munching (systemd)", "Fidrua 正在运行 (系统服务)"},
	"opt_view_status":    {"View status", "查看状态"},
	"opt_stop_service":   {"Stop service", "停止服务"},
	"opt_restart_service":{"Restart service", "重启服务"},
	"opt_edit_config":    {"Edit configuration", "修改配置"},
	"opt_uninstall":      {"Uninstall service", "卸载服务"},
	
	// Service stopped menu
	"service_stopped":    {"Fidrua is installed but stopped", "Fidrua 已安装但未运行"},
	"opt_start_service":  {"Start service", "启动服务"},
	
	// Background process menu
	"bg_running":         {"Fidrua is munching (background)", "Fidrua 正在运行 (后台进程)"},
	"opt_stop_bg":        {"Stop background process", "停止后台进程"},
	
	// Foreground controls
	"fg_controls":        {"[b] Background  [s] Install service  [q] Quit", "[b] 转后台  [s] 安装服务  [q] 退出"},
	"switching_bg":       {"Switching to background...", "正在切换到后台..."},
	"bg_started":         {"Running in background. PID: %d", "已在后台运行，PID: %d"},
	
	// Actions
	"stopping":           {"Stopping Fidrua...", "正在停止 Fidrua..."},
	"starting":           {"Starting Fidrua...", "正在启动 Fidrua..."},
	"restarting":         {"Restarting Fidrua...", "正在重启 Fidrua..."},
	"munching":           {"Fidrua starts munching...", "Fidrua 开始吃资源..."},
	"stopped":            {"Fidrua stopped", "Fidrua 已停止"},
	"bye":                {"Fidrua is full. Bye bye!", "Fidrua 吃饱了，再见！"},
	"spitting":           {"Fidrua spitting out resources...", "Fidrua 正在吐出资源..."},
	
	// Install
	"adopt_title":        {"Adopt Fidrua", "领养 Fidrua"},
	"enter_free_pct":     {"Enter target FREE percentage for each resource.", "输入每项资源要保留的空闲百分比"},
	"use_default":        {"Press Enter to use default value.", "按回车使用默认值"},
	"cpu_free":           {"CPU free %", "CPU 空闲 %"},
	"mem_free":           {"Memory free %", "内存空闲 %"},
	"disk_free":          {"Disk free %", "磁盘空闲 %"},
	"config_summary":     {"Configuration", "配置摘要"},
	"confirm_adopt":      {"Adopt Fidrua with these settings? [Y/n]", "使用这些设置领养 Fidrua? [Y/n]"},
	"need_sudo":          {"Permission denied. Run with sudo", "权限不足，请使用 sudo 运行"},
	"adopted":            {"Fidrua adopted and munching!", "Fidrua 已领养并开始工作！"},
	
	// Uninstall
	"confirm_release":    {"Are you sure you want to release Fidrua? [y/N]", "确定要放生 Fidrua 吗? [y/N]"},
	"releasing":          {"Releasing Fidrua...", "正在放生 Fidrua..."},
	"released":           {"Fidrua released to the wild!", "Fidrua 已放归自然！"},
	
	// Status display
	"appetite":           {"FIDRUA'S APPETITE", "FIDRUA 的胃口"},
	"saving_for_you":     {"Saving for you", "为你保留"},
	"tummy":              {"FIDRUA'S TUMMY", "FIDRUA 的肚子"},
	"resource":           {"RESOURCE", "资源"},
	"others":             {"OTHERS", "其他"},
	"fidrua":             {"FIDRUA", "FIDRUA"},
	"total":              {"TOTAL", "总计"},
	"target":             {"TARGET", "目标"},
	"details":            {"DETAILS", "详情"},
	"disks":              {"DISKS", "磁盘"},
	"ctrl_c_exit":        {"Ctrl+C to exit", "Ctrl+C 退出"},
}

func T(key string) string {
	if t, ok := texts[key]; ok {
		return t[currentLang]
	}
	return key
}

// DiskInfo holds information about a single disk/partition
type DiskInfo struct {
	MountPoint string
	Device     string
	FsType     string
	File       string // file path for consumption
	Used       int64  // bytes we're consuming
}

type ResourceConsumer struct {
	mu sync.Mutex

	// Target: keep this much resource FREE (percentage 0-100)
	targetFreeCPU  float64
	targetFreeMem  float64
	targetFreeDisk float64

	// Memory consumption
	memChunks [][]byte

	// CPU consumption
	cpuDuty     int32 // duty cycle 0-100 (atomic)
	cpuStopChan chan struct{}
	cpuWg       sync.WaitGroup

	// Disk consumption (multi-disk support)
	disks []*DiskInfo

	// System info
	totalMem  uint64
	numCPU    int

	// Mode
	daemonMode bool

	stopChan chan struct{}
}

func NewResourceConsumer(freeCPU, freeMem, freeDisk float64, daemon bool) *ResourceConsumer {
	numCPU := runtime.NumCPU()
	rc := &ResourceConsumer{
		targetFreeCPU:  freeCPU,
		targetFreeMem:  freeMem,
		targetFreeDisk: freeDisk,
		numCPU:         numCPU,
		daemonMode:     daemon,
		stopChan:       make(chan struct{}),
		cpuStopChan:    make(chan struct{}),
	}
	// Detect all mounted filesystems
	rc.disks = rc.detectDisks()
	return rc
}

// detectDisks finds all mounted filesystems that we should consume
func (rc *ResourceConsumer) detectDisks() []*DiskInfo {
	var disks []*DiskInfo
	seen := make(map[string]bool) // track seen devices to avoid duplicates

	file, err := os.Open("/proc/mounts")
	if err != nil {
		// Fallback to /tmp
		return []*DiskInfo{{
			MountPoint: "/tmp",
			Device:     "unknown",
			FsType:     "unknown",
			File:       "/tmp/fidrua_feast.dat",
		}}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]

		// Skip non-physical filesystems
		if !strings.HasPrefix(device, "/dev/") {
			continue
		}

		// Skip special filesystems
		skipFs := []string{"devtmpfs", "devpts", "tmpfs", "sysfs", "proc", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "fusectl", "configfs", "hugetlbfs", "mqueue", "pstore", "bpf", "autofs"}
		isSkip := false
		for _, skip := range skipFs {
			if fsType == skip {
				isSkip = true
				break
			}
		}
		if isSkip {
			continue
		}

		// Skip if we've seen this device (handles bind mounts)
		if seen[device] {
			continue
		}
		seen[device] = true

		// Skip read-only mounts or special mount points
		if strings.HasPrefix(mountPoint, "/snap") ||
			strings.HasPrefix(mountPoint, "/boot/efi") ||
			strings.HasPrefix(mountPoint, "/run") {
			continue
		}

		// Find a writable location on this mount
		dataFile := findWritableLocation(mountPoint)
		if dataFile == "" {
			continue // No writable location found
		}

		disks = append(disks, &DiskInfo{
			MountPoint: mountPoint,
			Device:     device,
			FsType:     fsType,
			File:       dataFile,
		})
	}

	// Fallback if no disks detected
	if len(disks) == 0 {
		return []*DiskInfo{{
			MountPoint: "/tmp",
			Device:     "unknown",
			FsType:     "unknown",
			File:       "/tmp/fidrua_feast.dat",
		}}
	}

	return disks
}

// findWritableLocation finds a writable path on the given mount point for our data file
func findWritableLocation(mountPoint string) string {
	// Generate safe name from mount point
	safeName := strings.ReplaceAll(mountPoint, "/", "_")
	if safeName == "_" {
		safeName = "_root"
	}
	fileName := fmt.Sprintf(".fidrua_feast%s.dat", safeName)

	// Try different locations in order of preference
	candidates := []string{
		filepath.Join(mountPoint, "tmp"),           // /mountpoint/tmp/
		filepath.Join(mountPoint, "var", "tmp"),    // /mountpoint/var/tmp/
		filepath.Join(mountPoint, ".cache"),        // /mountpoint/.cache/
		mountPoint,                                  // /mountpoint/ (root of mount)
	}

	for _, dir := range candidates {
		// Check if directory exists (or can be created for .cache)
		if dir == filepath.Join(mountPoint, ".cache") {
			os.MkdirAll(dir, 0755) // Try to create .cache if not exists
		}

		testFile := filepath.Join(dir, ".fidrua_test")
		f, err := os.Create(testFile)
		if err == nil {
			f.Close()
			os.Remove(testFile)
			return filepath.Join(dir, fileName)
		}
	}

	return "" // No writable location found
}

// cleanupStaleFiles removes data files from previous runs that weren't cleaned up properly
func cleanupStaleFiles() {
	// Check if another instance is actually running
	if isProcessRunning() {
		return // Don't clean if process is alive
	}

	// Clean up stale PID file
	os.Remove(pidFile)
	os.Remove(statusFile)

	// Find and remove all fidrua data files
	// Check all mount points
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		mountPoint := fields[1]
		
		// Look for fidrua data files in this mount point
		matches, _ := filepath.Glob(filepath.Join(mountPoint, ".fidrua_feast*.dat"))
		for _, f := range matches {
			os.Remove(f)
		}
	}
}

// isProcessRunning checks if the PID in pidFile is still running
// isProcessRunning checks if PID file process is alive AND is fidruafeast
func isProcessRunning() bool {
	pid := getRunningPid()
	return pid > 0
}

// getRunningPid returns the PID if fidrua is running, 0 otherwise
func getRunningPid() int {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0
	}
	
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err != nil {
		return 0
	}
	
	// Check if process exists
	process, err := os.FindProcess(pid)
	if err != nil {
		return 0
	}
	
	// On Unix, FindProcess always succeeds, so we need to send signal 0 to check
	if err = process.Signal(syscall.Signal(0)); err != nil {
		return 0
	}
	
	// Verify it's actually fidruafeast by checking cmdline
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return 0
	}
	if !strings.Contains(string(cmdline), "fidruafeast") && !strings.Contains(string(cmdline), "resource-consumer") {
		return 0 // PID reused by another process
	}
	
	return pid
}

// isSystemdInstalled checks if systemd service is installed
func isSystemdInstalled() bool {
	_, err := os.Stat("/etc/systemd/system/fidruafeast.service")
	return err == nil
}

// isSystemdRunning checks if systemd service is running
func isSystemdRunning() bool {
	out, err := exec.Command("systemctl", "is-active", "fidruafeast").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

// SystemState represents the current state of fidrua
type SystemState int

const (
	StateFirstRun      SystemState = iota // No service, no background process
	StateServiceRunning                    // Systemd service is running
	StateServiceStopped                    // Systemd installed but stopped
	StateBackgroundRun                     // Background process running (no systemd)
)

// getSystemState determines current system state
func getSystemState() SystemState {
	serviceInstalled := isSystemdInstalled()
	serviceRunning := isSystemdRunning()
	bgRunning := isProcessRunning()
	
	if serviceInstalled {
		if serviceRunning {
			return StateServiceRunning
		}
		return StateServiceStopped
	}
	
	if bgRunning {
		return StateBackgroundRun
	}
	
	return StateFirstRun
}

// writePidFile writes the current PID to the pid file
func writePidFile() {
	os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
}

// saveLang saves current language preference
func saveLang() {
	os.WriteFile(langFile, []byte(fmt.Sprintf("%d", currentLang)), 0644)
}

// loadLang loads language preference
func loadLang() bool {
	data, err := os.ReadFile(langFile)
	if err != nil {
		return false
	}
	var lang int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &lang); err != nil {
		return false
	}
	if lang == 0 || lang == 1 {
		currentLang = Lang(lang)
		return true
	}
	return false
}

// Get system memory info (returns total and used by OTHER processes)
func (rc *ResourceConsumer) getMemInfo() (total, otherUsed uint64, err error) {
	var info syscall.Sysinfo_t
	if err = syscall.Sysinfo(&info); err != nil {
		return
	}
	total = info.Totalram * uint64(info.Unit)
	available := (info.Freeram + info.Bufferram) * uint64(info.Unit)

	rc.mu.Lock()
	ourMem := uint64(len(rc.memChunks) * chunkSize)
	rc.mu.Unlock()

	totalUsed := total - available
	if totalUsed > ourMem {
		otherUsed = totalUsed - ourMem
	} else {
		otherUsed = 0
	}
	return
}

// Get disk info for a specific disk (returns total and used by OTHER files)
func (rc *ResourceConsumer) getDiskInfo(disk *DiskInfo) (total, otherUsed uint64, err error) {
	var stat syscall.Statfs_t
	if err = syscall.Statfs(disk.MountPoint, &stat); err != nil {
		return
	}
	total = stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)

	ourDisk := uint64(disk.Used)

	totalUsed := total - available
	if totalUsed > ourDisk {
		otherUsed = totalUsed - ourDisk
	} else {
		otherUsed = 0
	}
	return
}

// Get aggregated disk info across all disks
func (rc *ResourceConsumer) getAllDiskInfo() (totalAll, otherUsedAll, ourUsedAll uint64) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	for _, disk := range rc.disks {
		total, otherUsed, err := rc.getDiskInfo(disk)
		if err == nil {
			totalAll += total
			otherUsedAll += otherUsed
			ourUsedAll += uint64(disk.Used)
		}
	}
	return
}

// Get CPU load (returns load from OTHER processes)
func (rc *ResourceConsumer) getCPUOtherLoad() float64 {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return 0
	}
	load1 := float64(info.Loads[0]) / 65536.0

	duty := atomic.LoadInt32(&rc.cpuDuty)
	ourLoad := float64(rc.numCPU) * float64(duty) / 100.0

	otherLoad := load1 - ourLoad
	if otherLoad < 0 {
		otherLoad = 0
	}
	return otherLoad
}

// CPU worker goroutine with duty cycle control
func (rc *ResourceConsumer) cpuWorkerFunc(id int) {
	defer rc.cpuWg.Done()
	for {
		select {
		case <-rc.cpuStopChan:
			return
		default:
			duty := atomic.LoadInt32(&rc.cpuDuty)
			if duty <= 0 {
				time.Sleep(50 * time.Millisecond)
				continue
			}

			workTime := time.Duration(duty) * time.Millisecond
			sleepTime := time.Duration(100-duty) * time.Millisecond

			start := time.Now()
			for time.Since(start) < workTime {
				for i := 0; i < 1000000; i++ {
					_ = i * i
				}
			}

			if sleepTime > 0 {
				time.Sleep(sleepTime)
			}
		}
	}
}

// Set CPU duty cycle (0-100)
func (rc *ResourceConsumer) setCPUDuty(duty int) {
	if duty < 0 {
		duty = 0
	}
	if duty > 100 {
		duty = 100
	}
	atomic.StoreInt32(&rc.cpuDuty, int32(duty))
}

// Set memory consumption
func (rc *ResourceConsumer) setMemory(targetBytes uint64) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	currentBytes := uint64(len(rc.memChunks) * chunkSize)

	if targetBytes > currentBytes {
		chunksNeeded := int((targetBytes - currentBytes) / chunkSize)
		for i := 0; i < chunksNeeded; i++ {
			chunk := make([]byte, chunkSize)
			for j := 0; j < len(chunk); j += 4096 {
				chunk[j] = 1
			}
			rc.memChunks = append(rc.memChunks, chunk)
		}
	} else if targetBytes < currentBytes {
		chunksToKeep := int(targetBytes / chunkSize)
		if chunksToKeep < len(rc.memChunks) {
			rc.memChunks = rc.memChunks[:chunksToKeep]
			runtime.GC()
		}
	}
}

// Set disk consumption for a single disk
func (rc *ResourceConsumer) setDiskForOne(disk *DiskInfo, targetBytes int64) error {
	if targetBytes < 0 {
		targetBytes = 0
	}

	if targetBytes == 0 {
		os.Remove(disk.File)
		disk.Used = 0
		return nil
	}

	if targetBytes < disk.Used {
		os.Remove(disk.File)
		disk.Used = 0
	}

	f, err := os.OpenFile(disk.File, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if disk.Used < targetBytes {
		err = syscall.Fallocate(int(f.Fd()), 0, disk.Used, targetBytes-disk.Used)
		if err != nil {
			buf := make([]byte, 1024*1024)
			for i := range buf {
				buf[i] = 0
			}
			f.Seek(disk.Used, 0)
			for written := disk.Used; written < targetBytes; {
				toWrite := int64(len(buf))
				if written+toWrite > targetBytes {
					toWrite = targetBytes - written
				}
				n, err := f.Write(buf[:toWrite])
				if err != nil {
					return err
				}
				written += int64(n)
			}
		}
	}
	disk.Used = targetBytes
	return nil
}

// Clear all disk consumption
func (rc *ResourceConsumer) clearAllDisks() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	for _, disk := range rc.disks {
		os.Remove(disk.File)
		disk.Used = 0
	}
}

func (rc *ResourceConsumer) getMemUsed() uint64 {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return uint64(len(rc.memChunks) * chunkSize)
}

func (rc *ResourceConsumer) getTotalDiskUsed() int64 {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var total int64
	for _, disk := range rc.disks {
		total += disk.Used
	}
	return total
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func (rc *ResourceConsumer) Run() {
	// Start CPU worker pool
	for i := 0; i < rc.numCPU; i++ {
		rc.cpuWg.Add(1)
		go rc.cpuWorkerFunc(i)
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	rc.adjust()
	rc.updateStatus()

	for {
		select {
		case <-rc.stopChan:
			rc.cleanup()
			return
		case <-ticker.C:
			rc.adjust()
			rc.updateStatus()
		}
	}
}

func (rc *ResourceConsumer) getStatusString() string {
	totalMem, otherMemUsed, _ := rc.getMemInfo()
	totalDisk, otherDiskUsed, ourDiskUsed := rc.getAllDiskInfo()
	otherCPULoad := rc.getCPUOtherLoad()

	ourMem := rc.getMemUsed()
	ourCPUDuty := atomic.LoadInt32(&rc.cpuDuty)

	otherMemPct := float64(otherMemUsed) / float64(totalMem) * 100
	var otherDiskPct, ourDiskPct float64
	if totalDisk > 0 {
		otherDiskPct = float64(otherDiskUsed) / float64(totalDisk) * 100
		ourDiskPct = float64(ourDiskUsed) / float64(totalDisk) * 100
	}
	otherCPUPct := (otherCPULoad / float64(rc.numCPU)) * 100
	if otherCPUPct > 100 {
		otherCPUPct = 100
	}

	ourMemPct := float64(ourMem) / float64(totalMem) * 100
	ourCPUPct := float64(ourCPUDuty)

	totalMemPct := otherMemPct + ourMemPct
	totalDiskPct := otherDiskPct + ourDiskPct
	totalCPUPct := otherCPUPct + ourCPUPct
	if totalMemPct > 100 {
		totalMemPct = 100
	}
	if totalDiskPct > 100 {
		totalDiskPct = 100
	}
	if totalCPUPct > 100 {
		totalCPUPct = 100
	}

	var sb strings.Builder
	
	sb.WriteString("\n")
	sb.WriteString("  \033[36m🐕 FIDRUA'S APPETITE\033[0m\n")
	sb.WriteString(fmt.Sprintf("    Saving for you -> CPU: %.1f%% | MEM: %.1f%% | DISK: %.1f%%\n",
		rc.targetFreeCPU, rc.targetFreeMem, rc.targetFreeDisk))
	sb.WriteString(fmt.Sprintf("    CPU Cores: %d | Disks: %d\n", rc.numCPU, len(rc.disks)))
	sb.WriteString("\n")
	sb.WriteString("  \033[33m🦴 FIDRUA'S TUMMY\033[0m\n")
	sb.WriteString("    RESOURCE     OTHERS     FIDRUA      TOTAL     TARGET\n")
	sb.WriteString("    --------     ------     ------      -----     ------\n")
	sb.WriteString(fmt.Sprintf("    CPU        %7.1f%%    %7.1f%%    %7.1f%%    %7.1f%%\n",
		otherCPUPct, ourCPUPct, totalCPUPct, 100-rc.targetFreeCPU))
	sb.WriteString(fmt.Sprintf("    Memory     %7.1f%%    %7.1f%%    %7.1f%%    %7.1f%%\n",
		otherMemPct, ourMemPct, totalMemPct, 100-rc.targetFreeMem))
	sb.WriteString(fmt.Sprintf("    Disk(all)  %7.1f%%    %7.1f%%    %7.1f%%    %7.1f%%\n",
		otherDiskPct, ourDiskPct, totalDiskPct, 100-rc.targetFreeDisk))
	sb.WriteString("\n")
	sb.WriteString("  \033[2m📊 DETAILS\033[0m\n")
	sb.WriteString(fmt.Sprintf("    Memory: %s total | %s others | %s Fidrua ate\n",
		formatBytes(totalMem), formatBytes(otherMemUsed), formatBytes(ourMem)))
	sb.WriteString(fmt.Sprintf("    Disk:   %s total | %s others | %s Fidrua ate\n",
		formatBytes(totalDisk), formatBytes(otherDiskUsed), formatBytes(ourDiskUsed)))
	
	// Show per-disk details
	if len(rc.disks) >= 1 {
		sb.WriteString("\n")
		sb.WriteString("  \033[2m💾 DISKS\033[0m")
		// Show global overflow warning
		if totalDisk > 0 && otherDiskPct >= (100-rc.targetFreeDisk) {
			sb.WriteString(" \033[33m(global usage already over target)\033[0m")
		}
		sb.WriteString("\n")
		targetUsagePct := 100 - rc.targetFreeDisk
		rc.mu.Lock()
		for _, disk := range rc.disks {
			total, otherUsed, _ := rc.getDiskInfo(disk)
			if total > 0 {
				otherPct := float64(otherUsed) / float64(total) * 100
				usedPct := float64(otherUsed+uint64(disk.Used)) / float64(total) * 100
				if otherPct >= targetUsagePct {
					// Already over target, show warning
					sb.WriteString(fmt.Sprintf("    %-12s %s total | %.1f%% used | \033[33mfull (%.1f%%)\033[0m\n",
						disk.MountPoint, formatBytes(total), usedPct, otherPct))
				} else {
					sb.WriteString(fmt.Sprintf("    %-12s %s total | %.1f%% used | %s Fidrua ate\n",
						disk.MountPoint, formatBytes(total), usedPct, formatBytes(uint64(disk.Used))))
				}
			}
		}
		rc.mu.Unlock()
	}
	
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("  [%s] Ctrl+C to exit\n", time.Now().Format("15:04:05")))

	return sb.String()
}

func (rc *ResourceConsumer) updateStatus() {
	status := rc.getStatusString()

	// Write to status file for daemon mode
	os.WriteFile(statusFile, []byte(status), 0644)

	// Print to terminal if not daemon mode
	if !rc.daemonMode {
		// Move cursor to top-left and overwrite
		fmt.Print("\033[H")
		fmt.Print(status)
	}
}

func (rc *ResourceConsumer) adjust() {
	// === CPU ===
	otherCPULoad := rc.getCPUOtherLoad()
	otherCPUPct := (otherCPULoad / float64(rc.numCPU)) * 100
	targetUsagePct := 100 - rc.targetFreeCPU
	weNeedPct := targetUsagePct - otherCPUPct
	if weNeedPct < 0 {
		weNeedPct = 0
	}
	if weNeedPct > 100 {
		weNeedPct = 100
	}
	rc.setCPUDuty(int(weNeedPct))

	// === Memory ===
	totalMem, otherMemUsed, err := rc.getMemInfo()
	if err == nil {
		otherMemPct := float64(otherMemUsed) / float64(totalMem) * 100
		targetUsagePct := 100 - rc.targetFreeMem
		weNeedPct := targetUsagePct - otherMemPct
		if weNeedPct < 0 {
			weNeedPct = 0
		}
		weNeedBytes := uint64(weNeedPct / 100 * float64(totalMem))
		rc.setMemory(weNeedBytes)
	}

	// === Disk (global calculation with proportional distribution) ===
	rc.mu.Lock()
	rc.adjustDisksGlobal()
	rc.mu.Unlock()
}

// adjustDisksGlobal calculates disk consumption globally and distributes proportionally
func (rc *ResourceConsumer) adjustDisksGlobal() {
	targetUsagePct := 100 - rc.targetFreeDisk

	// Step 1: Calculate global totals
	var globalTotal, globalOtherUsed uint64
	type diskState struct {
		disk      *DiskInfo
		total     uint64
		otherUsed uint64
		maxCanEat int64 // max bytes this disk can consume (to reach target)
		isTmp     bool  // is this the /tmp disk?
	}
	var states []diskState

	for _, disk := range rc.disks {
		total, otherUsed, err := rc.getDiskInfo(disk)
		if err != nil || total == 0 {
			continue
		}
		globalTotal += total
		globalOtherUsed += otherUsed

		// Max this disk can eat = target% of total - current other usage
		maxCanEat := int64(float64(total)*targetUsagePct/100) - int64(otherUsed)
		if maxCanEat < 0 {
			maxCanEat = 0
		}

		isTmp := strings.HasPrefix(disk.File, "/tmp") || strings.Contains(disk.File, "/tmp/")
		states = append(states, diskState{
			disk:      disk,
			total:     total,
			otherUsed: otherUsed,
			maxCanEat: maxCanEat,
			isTmp:     isTmp,
		})
	}

	if len(states) == 0 {
		return
	}

	// Step 2: Calculate global need
	globalTargetUsed := int64(float64(globalTotal) * targetUsagePct / 100)
	globalNeed := globalTargetUsed - int64(globalOtherUsed)
	if globalNeed <= 0 {
		// Already over target globally, clear all
		for _, s := range states {
			rc.setDiskForOne(s.disk, 0)
		}
		return
	}

	// Step 3: Initialize allocation map
	allocation := make(map[*DiskInfo]int64)
	for _, s := range states {
		allocation[s.disk] = 0
	}

	// Step 4: Priority - fill /tmp disk first
	remaining := globalNeed
	for i := range states {
		if states[i].isTmp && states[i].maxCanEat > 0 {
			eat := remaining
			if eat > states[i].maxCanEat {
				eat = states[i].maxCanEat
			}
			allocation[states[i].disk] = eat
			remaining -= eat
			states[i].maxCanEat = 0 // mark as full
			break
		}
	}

	// Step 5: Iteratively distribute remaining to other disks by capacity ratio
	for remaining > 0 {
		// Calculate total capacity of disks that can still eat
		var availableCapacity uint64
		for _, s := range states {
			if s.maxCanEat > 0 {
				availableCapacity += s.total
			}
		}
		if availableCapacity == 0 {
			break // No disk can eat more
		}

		// Distribute by ratio
		distributed := int64(0)
		for i := range states {
			if states[i].maxCanEat <= 0 {
				continue
			}
			// This disk's share based on capacity ratio
			share := int64(float64(remaining) * float64(states[i].total) / float64(availableCapacity))
			if share > states[i].maxCanEat {
				share = states[i].maxCanEat
			}
			allocation[states[i].disk] += share
			states[i].maxCanEat -= share
			distributed += share
		}

		if distributed == 0 {
			break // No progress, avoid infinite loop
		}
		remaining -= distributed
	}

	// Step 6: Apply allocations
	for _, s := range states {
		rc.setDiskForOne(s.disk, allocation[s.disk])
	}
}

func (rc *ResourceConsumer) cleanup() {
	if !rc.daemonMode {
		fmt.Print("\033[H\033[2J")
		fmt.Println("Fidrua spitting out resources...")
	}

	close(rc.cpuStopChan)
	rc.cpuWg.Wait()
	rc.setMemory(0)
	rc.clearAllDisks()
	os.Remove(statusFile)
	os.Remove(pidFile)

	if !rc.daemonMode {
		fmt.Println("Fidrua is full. Bye bye!")
	}
}

func (rc *ResourceConsumer) Stop() {
	close(rc.stopChan)
}

// isAnotherInstanceRunning checks if another instance is running
func showStatus() {
	// Initial check
	if _, err := os.ReadFile(statusFile); err != nil {
		fmt.Println("Error: Fidrua is not running. Wake him up first!")
		os.Exit(1)
	}

	// Setup signal handler for clean exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Hide cursor
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		// Clear screen and move to top
		fmt.Print("\033[2J\033[H")
		
		data, err := os.ReadFile(statusFile)
		if err != nil {
			fmt.Println("Error: Fidrua stopped eating!")
			return
		}
		fmt.Print(string(data))

		select {
		case <-sigChan:
			fmt.Print("\033[2J\033[H")
			return
		case <-ticker.C:
			continue
		}
	}
}

// selectLanguage prompts user to select language
func selectLanguage() {
	green := "\033[32m"
	cyan := "\033[36m"
	reset := "\033[0m"
	
	fmt.Printf("\n  %s── Language / 语言 ──%s\n\n", cyan, reset)
	fmt.Printf("  %s[1]%s English\n", green, reset)
	fmt.Printf("  %s[2]%s 中文\n\n", green, reset)
	
	for {
		choice := readLine("  Select / 选择: ")
		switch choice {
		case "1":
			currentLang = LangEN
			saveLang()
			return
		case "2":
			currentLang = LangZH
			saveLang()
			return
		default:
			fmt.Println("  Invalid / 无效")
		}
	}
}

// showMainMenu shows the appropriate menu based on system state
func showMainMenu() {
	state := getSystemState()
	
	switch state {
	case StateFirstRun:
		showFirstRunMenu()
	case StateServiceRunning:
		showServiceRunningMenu()
	case StateServiceStopped:
		showServiceStoppedMenu()
	case StateBackgroundRun:
		showBackgroundMenu()
	}
}

// showFirstRunMenu - no service, no background process
func showFirstRunMenu() {
	cyan := "\033[36m"
	green := "\033[32m"
	dim := "\033[2m"
	reset := "\033[0m"

	fmt.Printf("  %s── %s ──%s\n\n", cyan, T("main_menu"), reset)
	fmt.Printf("  %s[1]%s %s\n", green, reset, T("opt_adopt"))
	fmt.Printf("  %s[2]%s %s\n", green, reset, T("opt_background"))
	fmt.Printf("  %s[3]%s %s\n", green, reset, T("opt_foreground"))
	fmt.Printf("  %s[q]%s %s\n\n", green, reset, T("opt_quit"))

	for {
		choice := readLine(fmt.Sprintf("  %s%s:%s ", dim, T("select_option"), reset))
		
		switch strings.ToLower(choice) {
		case "1":
			interactiveSystemdInstall()
			return
		case "2":
			startBackground()
			return
		case "3":
			startForeground()
			return
		case "q", "quit", "exit", "":
			return
		default:
			fmt.Printf("  %s%s%s\n", dim, T("invalid_option"), reset)
		}
	}
}

// showServiceRunningMenu - systemd service is running
func showServiceRunningMenu() {
	cyan := "\033[36m"
	green := "\033[32m"
	yellow := "\033[33m"
	dim := "\033[2m"
	reset := "\033[0m"

	fmt.Printf("  %s⚡ %s%s\n\n", yellow, T("service_running"), reset)
	
	fmt.Printf("  %s── %s ──%s\n\n", cyan, T("main_menu"), reset)
	fmt.Printf("  %s[1]%s %s\n", green, reset, T("opt_view_status"))
	fmt.Printf("  %s[2]%s %s\n", green, reset, T("opt_stop_service"))
	fmt.Printf("  %s[3]%s %s\n", green, reset, T("opt_restart_service"))
	fmt.Printf("  %s[4]%s %s\n", green, reset, T("opt_edit_config"))
	fmt.Printf("  %s[5]%s %s\n", green, reset, T("opt_uninstall"))
	fmt.Printf("  %s[q]%s %s\n\n", green, reset, T("opt_quit"))

	for {
		choice := readLine(fmt.Sprintf("  %s%s:%s ", dim, T("select_option"), reset))
		
		switch strings.ToLower(choice) {
		case "1":
			showStatus()
			return
		case "2":
			fmt.Println()
			fmt.Printf("  %s ", T("stopping"))
			if err := exec.Command("systemctl", "stop", "fidruafeast").Run(); err == nil {
				fmt.Println("ok")
			} else {
				fmt.Printf("failed (%s)\n", T("need_sudo"))
			}
			return
		case "3":
			fmt.Println()
			fmt.Printf("  %s ", T("restarting"))
			if err := exec.Command("systemctl", "restart", "fidruafeast").Run(); err == nil {
				fmt.Println("ok")
			} else {
				fmt.Printf("failed (%s)\n", T("need_sudo"))
			}
			return
		case "4":
			editConfig()
			return
		case "5":
			fmt.Println()
			answer := strings.ToLower(readLine(fmt.Sprintf("  %s ", T("confirm_release"))))
			if answer == "y" || answer == "yes" {
				uninstallSystemd()
			} else {
				fmt.Printf("  %s\n", T("cancelled"))
			}
			return
		case "q", "quit", "exit", "":
			return
		default:
			fmt.Printf("  %s%s%s\n", dim, T("invalid_option"), reset)
		}
	}
}

// showServiceStoppedMenu - systemd installed but stopped
func showServiceStoppedMenu() {
	cyan := "\033[36m"
	green := "\033[32m"
	yellow := "\033[33m"
	dim := "\033[2m"
	reset := "\033[0m"

	fmt.Printf("  %s⏸ %s%s\n\n", yellow, T("service_stopped"), reset)
	
	fmt.Printf("  %s── %s ──%s\n\n", cyan, T("main_menu"), reset)
	fmt.Printf("  %s[1]%s %s\n", green, reset, T("opt_start_service"))
	fmt.Printf("  %s[2]%s %s\n", green, reset, T("opt_background"))
	fmt.Printf("  %s[3]%s %s\n", green, reset, T("opt_foreground"))
	fmt.Printf("  %s[4]%s %s\n", green, reset, T("opt_edit_config"))
	fmt.Printf("  %s[5]%s %s\n", green, reset, T("opt_uninstall"))
	fmt.Printf("  %s[q]%s %s\n\n", green, reset, T("opt_quit"))

	for {
		choice := readLine(fmt.Sprintf("  %s%s:%s ", dim, T("select_option"), reset))
		
		switch strings.ToLower(choice) {
		case "1":
			fmt.Println()
			fmt.Printf("  %s ", T("starting"))
			if err := exec.Command("systemctl", "start", "fidruafeast").Run(); err == nil {
				fmt.Println("ok")
			} else {
				fmt.Printf("failed (%s)\n", T("need_sudo"))
			}
			return
		case "2":
			startBackground()
			return
		case "3":
			startForeground()
			return
		case "4":
			editConfig()
			return
		case "5":
			fmt.Println()
			answer := strings.ToLower(readLine(fmt.Sprintf("  %s ", T("confirm_release"))))
			if answer == "y" || answer == "yes" {
				uninstallSystemd()
			} else {
				fmt.Printf("  %s\n", T("cancelled"))
			}
			return
		case "q", "quit", "exit", "":
			return
		default:
			fmt.Printf("  %s%s%s\n", dim, T("invalid_option"), reset)
		}
	}
}

// showBackgroundMenu - background process running (no systemd)
func showBackgroundMenu() {
	cyan := "\033[36m"
	green := "\033[32m"
	yellow := "\033[33m"
	dim := "\033[2m"
	reset := "\033[0m"
	
	pid := getRunningPid()

	fmt.Printf("  %s⚡ %s (PID: %d)%s\n\n", yellow, T("bg_running"), pid, reset)
	
	fmt.Printf("  %s── %s ──%s\n\n", cyan, T("main_menu"), reset)
	fmt.Printf("  %s[1]%s %s\n", green, reset, T("opt_view_status"))
	fmt.Printf("  %s[2]%s %s\n", green, reset, T("opt_stop_bg"))
	fmt.Printf("  %s[3]%s %s\n", green, reset, T("opt_adopt"))
	fmt.Printf("  %s[q]%s %s\n\n", green, reset, T("opt_quit"))

	for {
		choice := readLine(fmt.Sprintf("  %s%s:%s ", dim, T("select_option"), reset))
		
		switch strings.ToLower(choice) {
		case "1":
			showStatus()
			return
		case "2":
			stopBackgroundProcess()
			return
		case "3":
			// Stop background first, then install
			stopBackgroundProcess()
			interactiveSystemdInstall()
			return
		case "q", "quit", "exit", "":
			return
		default:
			fmt.Printf("  %s%s%s\n", dim, T("invalid_option"), reset)
		}
	}
}

// stopBackgroundProcess stops the background fidrua process
func stopBackgroundProcess() {
	pid := getRunningPid()
	if pid <= 0 {
		return
	}
	
	fmt.Printf("\n  %s ", T("stopping"))
	process, err := os.FindProcess(pid)
	if err == nil {
		process.Signal(syscall.SIGTERM)
		// Wait a bit for cleanup
		time.Sleep(2 * time.Second)
		fmt.Println("ok")
	} else {
		fmt.Println("failed")
	}
}

// startBackground starts fidrua in background mode
func startBackground() {
	exePath, _ := os.Executable()
	absPath, _ := filepath.Abs(exePath)
	
	// Get config values
	cpu, mem, disk := getConfigValues()
	
	// Start in background
	cmd := exec.Command(absPath, "-daemon", 
		"-cpu", fmt.Sprintf("%.1f", cpu),
		"-mem", fmt.Sprintf("%.1f", mem),
		"-disk", fmt.Sprintf("%.1f", disk))
	cmd.Start()
	
	time.Sleep(500 * time.Millisecond)
	
	// Check if started
	pid := getRunningPid()
	if pid > 0 {
		fmt.Printf("\n  "+T("bg_started")+"\n\n", pid)
	} else {
		fmt.Println("\n  Failed to start\n")
	}
}

// startForeground starts fidrua in foreground mode
func startForeground() {
	// Get config values
	cpu, mem, disk := getConfigValues()
	
	// Set global flags for main() to continue
	runForegroundAfterMenu = true
	foregroundCPU = cpu
	foregroundMem = mem
	foregroundDisk = disk
}

// getConfigValues prompts for config if needed or returns defaults
func getConfigValues() (cpu, mem, disk float64) {
	dim := "\033[2m"
	reset := "\033[0m"
	cyan := "\033[36m"
	
	fmt.Println()
	fmt.Printf("  %s── %s ──%s\n\n", cyan, T("adopt_title"), reset)
	fmt.Printf("  %s%s%s\n", dim, T("enter_free_pct"), reset)
	fmt.Printf("  %s%s%s\n\n", dim, T("use_default"), reset)
	
	cpu = readFloatWithDefault(fmt.Sprintf("  %s", T("cpu_free")), 45)
	mem = readFloatWithDefault(fmt.Sprintf("  %s", T("mem_free")), 45)
	disk = readFloatWithDefault(fmt.Sprintf("  %s", T("disk_free")), 45)
	
	return
}

// editConfig allows editing the systemd service config
func editConfig() {
	serviceFile := "/etc/systemd/system/fidruafeast.service"
	
	// Read current config
	data, err := os.ReadFile(serviceFile)
	if err != nil {
		fmt.Printf("\n  Error reading config: %v\n", err)
		return
	}
	
	// Parse current values
	var cpu, mem, disk float64 = 45, 45, 45
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ExecStart=") {
			parts := strings.Fields(line)
			for i, p := range parts {
				switch p {
				case "-cpu":
					if i+1 < len(parts) {
						fmt.Sscanf(parts[i+1], "%f", &cpu)
					}
				case "-mem":
					if i+1 < len(parts) {
						fmt.Sscanf(parts[i+1], "%f", &mem)
					}
				case "-disk":
					if i+1 < len(parts) {
						fmt.Sscanf(parts[i+1], "%f", &disk)
					}
				}
			}
		}
	}
	
	dim := "\033[2m"
	reset := "\033[0m"
	cyan := "\033[36m"
	
	fmt.Println()
	fmt.Printf("  %s── %s ──%s\n\n", cyan, T("opt_edit_config"), reset)
	fmt.Printf("  %s%s%s\n\n", dim, T("use_default"), reset)
	
	newCpu := readFloatWithDefault(fmt.Sprintf("  %s", T("cpu_free")), cpu)
	newMem := readFloatWithDefault(fmt.Sprintf("  %s", T("mem_free")), mem)
	newDisk := readFloatWithDefault(fmt.Sprintf("  %s", T("disk_free")), disk)
	
	if newCpu == cpu && newMem == mem && newDisk == disk {
		fmt.Printf("\n  %s\n", T("cancelled"))
		return
	}
	
	// Update service file
	exePath, _ := os.Executable()
	absPath, _ := filepath.Abs(exePath)
	
	serviceContent := fmt.Sprintf(`[Unit]
Description=FidruaFeast - Samoyed Resource Muncher
After=network.target

[Service]
Type=simple
ExecStart=%s -cpu %.1f -mem %.1f -disk %.1f -daemon
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
`, absPath, newCpu, newMem, newDisk)
	
	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		fmt.Printf("\n  %s\n", T("need_sudo"))
		return
	}
	
	exec.Command("systemctl", "daemon-reload").Run()
	
	fmt.Println()
	answer := strings.ToLower(readLine(fmt.Sprintf("  %s ", T("opt_restart_service")+"? [Y/n]")))
	if answer == "" || answer == "y" || answer == "yes" {
		fmt.Printf("\n  %s ", T("restarting"))
		if err := exec.Command("systemctl", "restart", "fidruafeast").Run(); err == nil {
			fmt.Println("ok")
		} else {
			fmt.Println("failed")
		}
	}
}

func installSystemd(cpu, mem, disk float64) {
	exePath, _ := os.Executable()
	absPath, _ := filepath.Abs(exePath)

	serviceContent := fmt.Sprintf(`[Unit]
Description=FidruaFeast - Samoyed Resource Muncher
After=network.target

[Service]
Type=simple
ExecStart=%s -cpu %.1f -mem %.1f -disk %.1f -daemon
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
`, absPath, cpu, mem, disk)

	serviceFile := "/etc/systemd/system/fidruafeast.service"

	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		fmt.Printf("Error: Cannot write service file (need sudo?): %v\n", err)
		os.Exit(1)
	}

	// Create symlink in /usr/local/bin for easy access
	symlinkPath := "/usr/local/bin/fidruafeast"
	os.Remove(symlinkPath) // Remove if exists
	if err := os.Symlink(absPath, symlinkPath); err != nil {
		fmt.Printf("Warning: Cannot create symlink: %v\n", err)
	} else {
		fmt.Printf("Created symlink: %s -> %s\n", symlinkPath, absPath)
	}

	// Run systemctl commands automatically
	fmt.Println("Preparing Fidrua......")
	
	cmds := []struct {
		args []string
		desc string
	}{
		{[]string{"systemctl", "daemon-reload"}, "Updating house rules"},
		{[]string{"systemctl", "enable", "fidruafeast"}, "Training Fidrua"},
		{[]string{"systemctl", "start", "fidruafeast"}, "Feeding Fidrua"},
	}

	for _, cmd := range cmds {
		fmt.Printf("  %s... ", cmd.desc)
		if err := exec.Command(cmd.args[0], cmd.args[1:]...).Run(); err != nil {
			fmt.Printf("failed: %v\n", err)
		} else {
			fmt.Println("ok")
		}
	}

	fmt.Println("")
	fmt.Println("Fidrua adopted and munching!")
	fmt.Println("Check on Fidrua: fidruafeast -status")
}

func uninstallSystemd() {
	serviceFile := "/etc/systemd/system/fidruafeast.service"
	symlinkPath := "/usr/local/bin/fidruafeast"
	hasErrors := false

	fmt.Println("Releasing Fidrua......")

	// Stop Fidrua
	fmt.Print("  Stopping Fidrua... ")
	if err := exec.Command("systemctl", "stop", "fidruafeast").Run(); err != nil {
		fmt.Println("skipped (not running)")
	} else {
		fmt.Println("ok")
	}

	// Disable service
	fmt.Print("  Untaming Fidrua... ")
	if err := exec.Command("systemctl", "disable", "fidruafeast").Run(); err != nil {
		fmt.Println("skipped")
	} else {
		fmt.Println("ok")
	}

	// Remove service file
	fmt.Print("  Clearing his bed... ")
	if err := os.Remove(serviceFile); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("skipped (not found)")
		} else if os.IsPermission(err) {
			fmt.Println("failed: permission denied")
			hasErrors = true
		} else {
			fmt.Printf("failed: %v\n", err)
			hasErrors = true
		}
	} else {
		fmt.Println("ok")
	}

	// Remove symlink
	fmt.Print("  Removing his leash... ")
	if err := os.Remove(symlinkPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("skipped (not found)")
		} else if os.IsPermission(err) {
			fmt.Println("failed: permission denied")
			hasErrors = true
		} else {
			fmt.Printf("failed: %v\n", err)
			hasErrors = true
		}
	} else {
		fmt.Println("ok")
	}

	// Reload systemd
	fmt.Print("  Updating house rules... ")
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		fmt.Println("failed")
		hasErrors = true
	} else {
		fmt.Println("ok")
	}

	// Clean up data files
	fmt.Print("  Cleaning up treats... ")
	removed := 0
	if err := os.Remove(statusFile); err == nil {
		removed++
	}
	if err := os.Remove(pidFile); err == nil {
		removed++
	}
	// Clean up all fidrua data files from all mount points
	file, err := os.Open("/proc/mounts")
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 {
				continue
			}
			mountPoint := fields[1]
			matches, _ := filepath.Glob(filepath.Join(mountPoint, ".fidrua_feast*.dat"))
			for _, f := range matches {
				if err := os.Remove(f); err == nil {
					removed++
				}
			}
		}
		file.Close()
	}
	fmt.Printf("ok (%d files)\n", removed)

	fmt.Println("")
	if hasErrors {
		fmt.Println("Release incomplete. Try: sudo fidruafeast -uninstall")
		os.Exit(1)
	} else {
		fmt.Println("Fidrua released to the wild!")
	}
}

var stdinScanner *bufio.Scanner

func getScanner() *bufio.Scanner {
	if stdinScanner == nil {
		stdinScanner = bufio.NewScanner(os.Stdin)
	}
	return stdinScanner
}

func readLine(prompt string) string {
	fmt.Print(prompt)
	scanner := getScanner()
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

func readFloatWithDefault(prompt string, defaultVal float64) float64 {
	input := readLine(fmt.Sprintf("%s [%.0f]: ", prompt, defaultVal))
	if input == "" {
		return defaultVal
	}
	var val float64
	if _, err := fmt.Sscanf(input, "%f", &val); err != nil {
		return defaultVal
	}
	return val
}

func interactiveSystemdInstall() {
	dim := "\033[2m"
	reset := "\033[0m"
	green := "\033[32m"
	cyan := "\033[36m"
	
	fmt.Println()
	fmt.Printf("  %s── Adopt Fidrua ──%s\n\n", cyan, reset)
	fmt.Printf("  %sEnter target FREE percentage for each resource.%s\n", dim, reset)
	fmt.Printf("  %sPress Enter to use default value.%s\n\n", dim, reset)
	
	cpu := readFloatWithDefault("  CPU free %", 45)
	mem := readFloatWithDefault("  Memory free %", 45)
	disk := readFloatWithDefault("  Disk free %", 45)
	
	// Validate
	if cpu < 0 || cpu > 100 || mem < 0 || mem > 100 || disk < 0 || disk > 100 {
		fmt.Println("\n  Error: Values must be between 0 and 100")
		os.Exit(1)
	}
	
	fmt.Println()
	fmt.Printf("  %sConfiguration:%s\n", cyan, reset)
	fmt.Printf("    CPU:    keep %.0f%% free (use %.0f%%)\n", cpu, 100-cpu)
	fmt.Printf("    Memory: keep %.0f%% free (use %.0f%%)\n", mem, 100-mem)
	fmt.Printf("    Disk:   keep %.0f%% free (use %.0f%%)\n", disk, 100-disk)
	fmt.Println()
	
	answer := strings.ToLower(readLine("  Adopt Fidrua with these treats? [Y/n]: "))
	if answer != "" && answer != "y" && answer != "yes" {
		fmt.Println("  Cancelled.")
		os.Exit(0)
	}
	
	fmt.Println()
	
	// Check if we have permission
	exePath, _ := os.Executable()
	absPath, _ := filepath.Abs(exePath)
	serviceFile := "/etc/systemd/system/fidruafeast.service"
	
	// Try to write
	serviceContent := fmt.Sprintf(`[Unit]
Description=FidruaFeast - Samoyed Resource Muncher
After=network.target

[Service]
Type=simple
ExecStart=%s -cpu %.1f -mem %.1f -disk %.1f -daemon
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
`, absPath, cpu, mem, disk)
	
	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		fmt.Printf("  %sPermission denied. Run with sudo:%s\n\n", dim, reset)
		fmt.Printf("  %s$%s sudo %s -install\n\n", green, reset, absPath)
		os.Exit(1)
	}

	// Create symlink
	symlinkPath := "/usr/local/bin/fidruafeast"
	os.Remove(symlinkPath)
	if err := os.Symlink(absPath, symlinkPath); err != nil {
		fmt.Printf("  Warning: Cannot create symlink: %v\n", err)
	}

	// Run systemctl commands
	fmt.Println("  Preparing Fidrua......")
	cmds := []struct {
		args []string
		desc string
	}{
		{[]string{"systemctl", "daemon-reload"}, "Updating house rules"},
		{[]string{"systemctl", "enable", "fidruafeast"}, "Training Fidrua"},
		{[]string{"systemctl", "start", "fidruafeast"}, "Feeding Fidrua"},
	}

	for _, cmd := range cmds {
		fmt.Printf("    %s... ", cmd.desc)
		if err := exec.Command(cmd.args[0], cmd.args[1:]...).Run(); err != nil {
			fmt.Printf("failed: %v\n", err)
		} else {
			fmt.Println("ok")
		}
	}

	fmt.Println()
	fmt.Println("  Fidrua adopted and munching!")
	fmt.Printf("  View status with: %sfidruafeast -status%s\n\n", cyan, reset)
	os.Exit(0)
}

const version = "1.0.0"

func printBanner() {
	white := "\033[97m"
	yellow := "\033[33m"
	cyan := "\033[36m"
	reset := "\033[0m"
	bold := "\033[1m"
	dim := "\033[2m"

	fmt.Println()
	fmt.Printf("%s%s", bold, white)
	fmt.Println("                                   __   __")
	fmt.Println("                                  /  \\_/  \\")
	fmt.Println("    .---------------.            (  o   o  )")
	fmt.Println("    | [*]  :::::::: |_ _ _ _ _ _ _/    V    \\")
	fmt.Println("    | ============= |____________(  \\___/  )")
	fmt.Println("    |_______________|              \\_______/")
	fmt.Printf("%s", reset)
	fmt.Println()
	fmt.Printf("  %s%sFidruaFeast%s %sv%s%s  %sSamoyed Resource Muncher%s\n", bold, cyan, reset, dim, version, reset, dim, reset)
	fmt.Println()
	fmt.Printf("  %sFidrua is hungry! Let him munch your idle resources%s\n", yellow, reset)
	fmt.Printf("  %sHe'll spit them back when you need them%s\n", yellow, reset)
	fmt.Println()
	fmt.Printf("  %sUsage: fidruafeast [-cpu N] [-mem N] [-disk N]%s\n", dim, reset)
	fmt.Printf("  %s       fidruafeast -h  for help%s\n", dim, reset)
	fmt.Println()
}

func printUsage() {
	printBanner()
	
	cyan := "\033[36m"
	green := "\033[32m"
	yellow := "\033[33m"
	reset := "\033[0m"
	dim := "\033[2m"

	fmt.Printf("%s─── FEEDING FIDRUA ────────────────────────────────────────────────%s\n\n", dim, reset)
	fmt.Printf("  %s$%s fidruafeast [OPTIONS]\n\n", green, reset)
	
	fmt.Printf("%s─── TREAT OPTIONS ─────────────────────────────────────────────────%s\n\n", dim, reset)
	fmt.Printf("  %s-cpu%s <float>    Keep this %% CPU for you   %s(default: 45)%s\n", cyan, reset, dim, reset)
	fmt.Printf("  %s-mem%s <float>    Keep this %% Memory for you %s(default: 45)%s\n", cyan, reset, dim, reset)
	fmt.Printf("  %s-disk%s <float>   Keep this %% Disk for you  %s(default: 45)%s\n", cyan, reset, dim, reset)
	fmt.Printf("  %s-daemon%s         Let Fidrua munch quietly\n", cyan, reset)
	fmt.Printf("  %s-status%s         Check how much Fidrua ate\n", cyan, reset)
	fmt.Printf("  %s-install%s        Adopt Fidrua (systemd service)\n", cyan, reset)
	fmt.Printf("  %s-uninstall%s      Release Fidrua to the wild\n", cyan, reset)
	fmt.Printf("  %s-h%s              Show this help\n\n", cyan, reset)

	fmt.Printf("%s─── EXAMPLES ──────────────────────────────────────────────────────%s\n\n", dim, reset)
	fmt.Printf("  %s# Let Fidrua feast (keep 45%% for yourself)%s\n", dim, reset)
	fmt.Printf("  %s$%s fidruafeast\n\n", green, reset)
	fmt.Printf("  %s# Control his appetite%s\n", dim, reset)
	fmt.Printf("  %s$%s fidruafeast -cpu 30 -mem 20 -disk 40\n\n", green, reset)
	fmt.Printf("  %s# Let him munch quietly%s\n", dim, reset)
	fmt.Printf("  %s$%s fidruafeast -daemon\n\n", green, reset)
	fmt.Printf("  %s# Check his tummy%s\n", dim, reset)
	fmt.Printf("  %s$%s fidruafeast -status\n\n", green, reset)
	fmt.Printf("  %s# Adopt Fidrua permanently%s\n", dim, reset)
	fmt.Printf("  %s$%s sudo fidruafeast -install\n\n", yellow, reset)
	fmt.Printf("  %s# Release Fidrua%s\n", dim, reset)
	fmt.Printf("  %s$%s sudo fidruafeast -uninstall\n\n", yellow, reset)
}

// Global variable to track if we should run foreground after menu
var runForegroundAfterMenu = false
var foregroundCPU, foregroundMem, foregroundDisk float64 = 45, 45, 45

// setupSignalHandler sets up signal handling for the consumer
func setupSignalHandler(rc *ResourceConsumer) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, 
		syscall.SIGINT,  // Ctrl+C
		syscall.SIGTERM, // kill command
		syscall.SIGHUP,  // terminal closed
		syscall.SIGQUIT, // Ctrl+\
	)

	go func() {
		<-sigChan
		rc.Stop()
	}()
}

func main() {
	freeCPU := flag.Float64("cpu", 45, "Target free CPU percentage (0-100)")
	freeMem := flag.Float64("mem", 45, "Target free memory percentage (0-100)")
	freeDisk := flag.Float64("disk", 45, "Target free disk percentage (0-100)")
	showStatusFlag := flag.Bool("status", false, "Show current status and exit")
	daemonMode := flag.Bool("daemon", false, "Run in daemon mode (no terminal output)")
	installFlag := flag.Bool("install", false, "Install systemd service")
	uninstallFlag := flag.Bool("uninstall", false, "Uninstall systemd service")
	showHelp := flag.Bool("h", false, "Show help")
	// Keep -file for backward compatibility but ignore it
	_ = flag.String("file", "", "(deprecated, auto-detected)")
	flag.Usage = printUsage
	flag.Parse()

	if *showHelp {
		printUsage()
		return
	}

	// Show status
	if *showStatusFlag {
		loadLang()
		showStatus()
		return
	}

	// Install systemd service
	if *installFlag {
		loadLang()
		installSystemd(*freeCPU, *freeMem, *freeDisk)
		return
	}

	// Uninstall systemd service
	if *uninstallFlag {
		loadLang()
		uninstallSystemd()
		return
	}

	if *freeCPU < 0 || *freeCPU > 100 || *freeMem < 0 || *freeMem > 100 || *freeDisk < 0 || *freeDisk > 100 {
		fmt.Println("Error: Free percentages must be between 0 and 100")
		os.Exit(1)
	}

	// Daemon mode - skip interactive
	if *daemonMode {
		// Check if another instance is running
		if isProcessRunning() {
			fmt.Println("Error: Fidrua is already busy munching!")
			os.Exit(1)
		}
		
		cleanupStaleFiles()
		writePidFile()
		
		rc := NewResourceConsumer(*freeCPU, *freeMem, *freeDisk, true)
		setupSignalHandler(rc)
		rc.Run()
		return
	}

	// Interactive mode
	// Clear screen and show banner
	fmt.Print("\033[2J\033[H")
	printBanner()
	
	// Load or select language
	if !loadLang() {
		selectLanguage()
		fmt.Print("\033[2J\033[H")
		printBanner()
	}
	
	// Show appropriate menu based on state
	showMainMenu()
	
	// Check if user selected foreground run
	if !runForegroundAfterMenu {
		return
	}
	
	// Run in foreground
	fmt.Printf("\n  %s\n\n", T("munching"))
	time.Sleep(1 * time.Second)
	
	// Clear and hide cursor
	fmt.Print("\033[2J\033[H\033[?25l")
	defer fmt.Print("\033[?25h")
	
	cleanupStaleFiles()
	writePidFile()

	rc := NewResourceConsumer(foregroundCPU, foregroundMem, foregroundDisk, false)

	// Ensure cleanup on panic
	defer func() {
		if r := recover(); r != nil {
			rc.cleanup()
			panic(r) // re-panic after cleanup
		}
	}()

	setupSignalHandler(rc)
	rc.Run()
}
