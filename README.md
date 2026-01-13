# 🐕 FidruaFeast

**Samoyed Resource Muncher** - Let Fidrua munch your idle VPS resources!

<p align="center">
  <img src="assets/banner.png" alt="Fidrua munching on server" width="600">
</p>

<p align="center">
  <a href="README_CN.md">中文</a> | English
</p>

## 🤔 What is this?

Some VPS providers reclaim "idle" resources from your server. FidruaFeast solves this by having Fidrua (a hungry Samoyed 🐕) munch on your idle CPU, memory, and disk - keeping them occupied so they won't be taken away.

When your system actually needs those resources, Fidrua will spit them back out!

## ✨ Features

- 🦴 **CPU Munching** - Consume idle CPU cycles
- 🦴 **Memory Munching** - Allocate unused memory  
- 🦴 **Disk Munching** - Fill up unused disk space (multi-disk support!)
- 💾 **Multi-Disk Support** - Automatically detects and munches all mounted disks
- 🔄 **Auto-adjust** - Automatically release resources when needed
- 📊 **Live Status** - Watch Fidrua eat in real-time
- 🏠 **Systemd Service** - Run as a background service
- 🎛️ **Management Menu** - Easy interactive control

## 📦 Installation

### Quick Install (Recommended)

```bash
# Download latest release
wget https://github.com/donma033x/fidruafeast/releases/latest/download/fidruafeast-linux-amd64.tar.gz

# Extract
tar -xzf fidruafeast-linux-amd64.tar.gz

# Make executable
chmod +x fidruafeast

# Install as service (will auto-start)
sudo ./fidruafeast -install
```

### Build from Source

```bash
git clone https://github.com/donma033x/FidruaFeast.git
cd FidruaFeast
go build -o fidruafeast main.go
```

## 🚀 Usage

### Basic Commands

```bash
# Show help
fidruafeast -h

# Run interactively (keep 45% free by default)
fidruafeast

# Custom resource targets
fidruafeast -cpu 30 -mem 20 -disk 40

# Run in background
fidruafeast -daemon

# Check Fidrua's status
fidruafeast -status
```

### Service Management

```bash
# Install as systemd service
sudo fidruafeast -install

# Uninstall service
sudo fidruafeast -uninstall
```

### Interactive Menu

When Fidrua is already running, launching `fidruafeast` shows a management menu:

```
⚡ Fidrua is already munching!

── Management Menu ──

[1] Watch Fidrua eat    # Live status monitoring
[2] Stop Fidrua         # Stop the service
[3] Wake up Fidrua      # Restart the service
[4] Release Fidrua      # Uninstall service
[q] Quit
```

## ⚙️ Options

| Option | Description | Default |
|--------|-------------|---------|
| `-cpu <N>` | Keep N% CPU free for you | 45 |
| `-mem <N>` | Keep N% Memory free for you | 45 |
| `-disk <N>` | Keep N% Disk free for you | 45 |
| `-daemon` | Run in background mode | - |
| `-status` | Watch Fidrua's tummy | - |
| `-install` | Adopt Fidrua (systemd service) | - |
| `-uninstall` | Release Fidrua to the wild | - |
| `-h` | Show help | - |

## 📊 Status Display

```
🐕 FIDRUA'S APPETITE
  Saving for you -> CPU: 45.0% | MEM: 45.0% | DISK: 45.0%
  CPU Cores: 2 | Disks: 3

🦴 FIDRUA'S TUMMY
  RESOURCE     OTHERS     FIDRUA      TOTAL     TARGET
  --------     ------     ------      -----     ------
  CPU            5.0%       50.0%       55.0%       55.0%
  Memory        30.0%       25.0%       55.0%       55.0%
  Disk(all)     40.0%       15.0%       55.0%       55.0%

📊 DETAILS
  Memory: 8.0 GB total | 2.4 GB others | 2.0 GB Fidrua ate
  Disk:   150 GB total | 60 GB others | 22.5 GB Fidrua ate

💾 DISKS
  /            50 GB total | 55.0% used | 7.5 GB Fidrua ate
  /home        50 GB total | 55.0% used | 7.5 GB Fidrua ate
  /data        50 GB total | 55.0% used | 7.5 GB Fidrua ate
```

## 💻 System Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Linux (kernel 2.6.23+) |
| **Arch** | amd64, arm64 |
| **Dependencies** | None (statically linked) |
| **Service Manager** | systemd (for `-install`) |

### Supported Distributions

✅ Ubuntu 16.04+, Debian 8+, CentOS 7+, RHEL 7+, Fedora, Arch Linux, and most modern Linux distributions.

⚠️ **Note**: The `-install` feature requires systemd. For non-systemd systems (Alpine, older distros), run manually with `nohup ./fidruafeast -daemon &`

## 🐕 Why "Fidrua"?

Fidrua is a Samoyed who loves to munch on things. He's fluffy, friendly, and always hungry - perfect for eating up those idle resources! When you need them back, he'll happily spit them out.

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

---

Made with ❤️ by [donma033x](https://github.com/donma033x)
