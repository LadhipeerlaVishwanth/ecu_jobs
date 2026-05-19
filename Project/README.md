# UDS Diagnostics - Raspberry Pi Executable

## Overview
This package contains everything needed to build and run the UDS Diagnostics
application as a **single standalone executable** on any Raspberry Pi running
Raspberry Pi OS (32-bit or 64-bit).

---

## Project Structure

```
uds_project/
├── main.py                   ← App entry point
├── config.json               ← Configuration file
├── build_on_pi.sh            ← Build script (run this on your Pi)
├── uds_diagnostics.service   ← Systemd service for auto-start on boot
├── uds_app.spec              ← PyInstaller spec (used automatically)
└── drivers/
    ├── __init__.py
    ├── config_loader.py
    ├── oled_display.py
    ├── button_input.py
    ├── uds_client.py
    ├── transfer_file.py
    ├── Parse_handler.py
    ├── can_logger.py
    └── report_generator.py
```

---

## Step-by-Step: Build on Raspberry Pi

### 1. Copy files to your Raspberry Pi
Transfer the entire `uds_project/` folder to your Pi (USB, SCP, etc.):

```bash
scp -r uds_project/ pi@<your-pi-ip>:/home/mobase/dfs/demo/udsoncan/
```

### 2. Make the build script executable
```bash
cd /home/mobase/dfs/demo/udsoncan
chmod +x build_on_pi.sh
```

### 3. Run the build script
```bash
./build_on_pi.sh
```
This will:
- Install all dependencies (RPi.GPIO, Pillow, python-can, udsoncan, etc.)
- Bundle everything into a single executable using PyInstaller
- Output the binary to: `dist/uds_diagnostics`

### 4. Run the application
```bash
sudo ./dist/uds_diagnostics
```

> **Note:** `sudo` is required for GPIO access and CAN interface control.

---

## Auto-Start on Boot (Optional)

To have the app start automatically when the Pi powers on:

```bash
# 1. Copy the service file
sudo cp uds_diagnostics.service /etc/systemd/system/

# 2. Reload systemd and enable the service
sudo systemctl daemon-reload
sudo systemctl enable uds_diagnostics
sudo systemctl start uds_diagnostics

# 3. Check status
sudo systemctl status uds_diagnostics
```

To view live logs:
```bash
sudo journalctl -u uds_diagnostics -f
```

To stop auto-start:
```bash
sudo systemctl disable uds_diagnostics
```

---

## Compatibility

| Model              | OS             | Supported |
|--------------------|----------------|-----------|
| Raspberry Pi 3B/3B+| RPi OS 32-bit  | ✅        |
| Raspberry Pi 4     | RPi OS 32/64-bit | ✅      |
| Raspberry Pi 5     | RPi OS 64-bit  | ✅        |
| Raspberry Pi Zero 2| RPi OS 32-bit  | ✅        |

---

## Troubleshooting

**"RPi.GPIO not found"**
```bash
sudo apt-get install python3-rpi.gpio
```

**"CAN interface not found"**
Make sure your CAN HAT is connected and the kernel module is loaded:
```bash
sudo modprobe mcp251x
```

**"Permission denied on GPIO"**
Always run with `sudo`:
```bash
sudo ./dist/uds_diagnostics
```

**Build fails with "adafruit" error**
```bash
pip3 install adafruit-blinka adafruit-circuitpython-ssd1306 --break-system-packages
```

---

## Notes
- The `config.json` file is bundled inside the executable.
- The app reads `testcase.txt` from the input path defined in `transfer_file.py`.
- Log output goes to `uds_debug.log` in the working directory.
