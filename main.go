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
	chunkSize     = 10 * 1024 * 1024  // 10MB per memory chunk
	checkInterval = 2 * time.Second
)

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

		// Check if we can write to this mount point
		testFile := filepath.Join(mountPoint, ".fidrua_test")
		if f, err := os.Create(testFile); err == nil {
			f.Close()
			os.Remove(testFile)
		} else {
			continue // Not writable
		}

		// Generate unique filename for this mount
		safeName := strings.ReplaceAll(mountPoint, "/", "_")
		if safeName == "_" {
			safeName = "_root"
		}
		dataFile := filepath.Join(mountPoint, fmt.Sprintf(".fidrua_feast%s.dat", safeName))

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
	
	// Show per-disk details if multiple disks
	if len(rc.disks) > 1 {
		sb.WriteString("\n")
		sb.WriteString("  \033[2m💾 DISKS\033[0m\n")
		rc.mu.Lock()
		for _, disk := range rc.disks {
			total, otherUsed, _ := rc.getDiskInfo(disk)
			if total > 0 {
				usedPct := float64(otherUsed+uint64(disk.Used)) / float64(total) * 100
				sb.WriteString(fmt.Sprintf("    %-12s %s total | %.1f%% used | %s Fidrua ate\n",
					disk.MountPoint, formatBytes(total), usedPct, formatBytes(uint64(disk.Used))))
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

	// === Disk (per-disk adjustment) ===
	rc.mu.Lock()
	for _, disk := range rc.disks {
		totalDisk, otherDiskUsed, err := rc.getDiskInfo(disk)
		if err == nil && totalDisk > 0 {
			otherDiskPct := float64(otherDiskUsed) / float64(totalDisk) * 100
			targetUsagePct := 100 - rc.targetFreeDisk
			weNeedPct := targetUsagePct - otherDiskPct
			if weNeedPct < 0 {
				weNeedPct = 0
			}
			weNeedBytes := int64(weNeedPct / 100 * float64(totalDisk))
			rc.setDiskForOne(disk, weNeedBytes)
		}
	}
	rc.mu.Unlock()
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

	if !rc.daemonMode {
		fmt.Println("Fidrua is full. Bye bye!")
	}
}

func (rc *ResourceConsumer) Stop() {
	close(rc.stopChan)
}

// isAnotherInstanceRunning checks if another instance is running by looking at processes
func isAnotherInstanceRunning() bool {
	// Get current PID
	myPid := os.Getpid()
	
	// Use pgrep to find fidruafeast daemon processes
	out, err := exec.Command("pgrep", "-f", "fidruafeast.*-daemon").Output()
	if err != nil {
		return false // No process found
	}
	
	// Check if any PID is not ours
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(line, "%d", &pid); err == nil {
			if pid != myPid {
				return true
			}
		}
	}
	return false
}

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

func showManagementMenu() {
	cyan := "\033[36m"
	green := "\033[32m"
	yellow := "\033[33m"
	dim := "\033[2m"
	reset := "\033[0m"

	// Clear screen and show banner
	fmt.Print("\033[2J\033[H")
	printBanner()

	fmt.Printf("  %s⚡ Fidrua is already munching!%s\n\n", yellow, reset)

	fmt.Printf("  %s── Management Menu ──%s\n\n", cyan, reset)
	fmt.Printf("  %s[1]%s Watch Fidrua eat\n", green, reset)
	fmt.Printf("  %s[2]%s Stop Fidrua\n", green, reset)
	fmt.Printf("  %s[3]%s Wake up Fidrua\n", green, reset)
	fmt.Printf("  %s[4]%s Release Fidrua\n", green, reset)
	fmt.Printf("  %s[q]%s Quit\n\n", green, reset)

	for {
		choice := readLine(fmt.Sprintf("  %sSelect option:%s ", dim, reset))
		
		switch strings.ToLower(choice) {
		case "1":
			showStatus()
			return
		case "2":
			fmt.Println()
			fmt.Print("  Stopping Fidrua... ")
			if err := exec.Command("systemctl", "stop", "fidruafeast").Run(); err == nil {
				fmt.Println("ok")
			} else {
				fmt.Println("failed (need sudo)")
			}
			return
		case "3":
			fmt.Println()
			fmt.Print("  Waking up Fidrua... ")
			if err := exec.Command("systemctl", "restart", "fidruafeast").Run(); err == nil {
				fmt.Println("ok")
			} else {
				fmt.Println("failed (need sudo)")
			}
			return
		case "4":
			fmt.Println()
			answer := strings.ToLower(readLine("  Are you sure you want to release Fidrua? [y/N]: "))
			if answer == "y" || answer == "yes" {
				uninstallSystemd()
			} else {
				fmt.Println("  Cancelled.")
			}
			return
		case "q", "quit", "exit", "":
			return
		default:
			fmt.Printf("  %sInvalid option. Enter 1-4 or q to quit.%s\n", dim, reset)
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
	// Clean up all fidrua data files
	matches, _ := filepath.Glob("/*/.fidrua_feast*.dat")
	for _, f := range matches {
		if err := os.Remove(f); err == nil {
			removed++
		}
	}
	// Also check common locations
	for _, dir := range []string{"/tmp", "/", "/home"} {
		local, _ := filepath.Glob(filepath.Join(dir, ".fidrua_feast*.dat"))
		for _, f := range local {
			if err := os.Remove(f); err == nil {
				removed++
			}
		}
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

func checkSystemdInstall(cpu, mem, disk float64) {
	serviceFile := "/etc/systemd/system/fidruafeast.service"
	if _, err := os.Stat(serviceFile); os.IsNotExist(err) {
		answer := strings.ToLower(readLine("  Fidrua not adopted yet. Adopt him now? [y/N]: "))
		if answer == "y" || answer == "yes" {
			interactiveSystemdInstall()
		}
		fmt.Println()
	}
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
		showStatus()
		return
	}

	// Install systemd service
	if *installFlag {
		installSystemd(*freeCPU, *freeMem, *freeDisk)
		return
	}

	// Uninstall systemd service
	if *uninstallFlag {
		uninstallSystemd()
		return
	}

	if *freeCPU < 0 || *freeCPU > 100 || *freeMem < 0 || *freeMem > 100 || *freeDisk < 0 || *freeDisk > 100 {
		fmt.Println("Error: Free percentages must be between 0 and 100")
		os.Exit(1)
	}

	// Check single instance
	if isAnotherInstanceRunning() {
		if *daemonMode {
			fmt.Println("Error: Fidrua is already busy munching!")
			os.Exit(1)
		}
		showManagementMenu()
		return
	}

	// Interactive mode setup
	if !*daemonMode {
		// Clear screen and show welcome first
		fmt.Print("\033[2J\033[H")
		printBanner()
		
		// Then check systemd
		checkSystemdInstall(*freeCPU, *freeMem, *freeDisk)
		
		fmt.Println("  Fidrua starts munching...")
		fmt.Println()
		time.Sleep(1 * time.Second)
		// Clear and hide cursor
		fmt.Print("\033[2J\033[H\033[?25l")
		// Show cursor on exit
		defer fmt.Print("\033[?25h")
	}

	rc := NewResourceConsumer(*freeCPU, *freeMem, *freeDisk, *daemonMode)

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		rc.Stop()
	}()

	rc.Run()
}
