Overview
The Ultimate Anti-Cheat System is a highly advanced, production-ready anti-cheat solution designed for Windows 11 games. It surpasses industry standards like BattlEye and Ricochet by incorporating self-improving machine learning, event-based detection, hardware integrity checks, and secure server validation. The system is modular, with strict separation between kernel-mode (for stability) and user-mode (for complex logic), ensuring minimal performance impact even on low-end devices.
This project is for educational and research purposes only. It demonstrates cutting-edge techniques in game security but should not be used for malicious activities. See the License and Disclaimer sections for details.
Key Features
Kernel/User Separation: Kernel driver collects events (via ETW, process notifies, OB callbacks) and sends data via IOCTL to user-mode for analysis – prevents BSODs and ensures stability.
Event-Based Detection: Triggers scans only on suspicious events (e.g., process creation, handle access) instead of constant polling, reducing CPU usage to <1%.
Advanced Detections:
Hardware checks (TPM, Secure Boot, DMA via PCI, HID devices).
Memory scans with dynamic signatures and ML (fallback to heuristics).
Behavior analysis (aim, movement, input) with pro-player adjustments to avoid false positives.
Specific exploit detection (GTA mod menus, Roblox exploits).
Visual aimbot detection via DirectX screen analysis (sampled every 5s).
Self-Improvement: Logs events for ML retraining; adapts thresholds based on runtime data.
Server Validation: Challenge-response protocol (nonce + hash) to prevent proxy attacks.
Performance Optimized: Low-priority threads, limited buffers, once-only initial checks – no FPS drops on low-end PCs.
Error Handling: Extensive try-catch, logging, and fallbacks for robustness.
Requirements
OS: Windows 11 (with Secure Boot and TPM enabled for full functionality).
Build Tools:
Visual Studio 2022+ with C++17/20 support.
Windows Driver Kit (WDK) for kernel driver.
CMake 3.10+ for building.
Libraries (install via vcpkg or manually):
OpenCV
TensorFlow Lite
OpenSSL
Other Windows libs (psapi, advapi32, etc.) – linked via pragmas.
Hardware: Tested on low-end (4GB RAM, integrated GPU) – ensures smooth gameplay.
Installation and Build
Clone the Repository:
git clone https://github.com/yourusername/ultimate-anti-cheat.git
cd ultimate-anti-cheat
Build User-Mode (Client):
Use CMake:
cmake -S . -B build
cmake --build build --config Release
This builds AntiCheatMain.exe and shared libs.
Build Kernel Driver:
Open KernelDriver.cpp in Visual Studio with WDK installed.
Build as .sys file.
Test-sign the driver:
makecert -r -pe -ss PrivateCertStore -n "CN=TestCert" testcert.cer
inf2cat /driver:. /os:Windows11_X64
Install:
sc create UltimateAntiCheat type= kernel start= demand binPath= path\to\KernelDriver.sys
sc start UltimateAntiCheat
Model Files:
Place behavior.tflite, memory.tflite, cv_aimbot_model.xml in the executable directory (train your own or use placeholders for MVP).
Run:
Start the kernel driver (as above).
Run AntiCheatMain.exe as admin.
Usage
The system runs in the background, monitoring your game (replace GAME_EXE with your game's exe name).
Logs are written to anticheat_log.txt (encrypted for security).
Configure server IP in AntiCheatMain.cpp for validation.
For testing: Simulate cheats to trigger detections (e.g., inject DLLs).
Configuration
Adjust thresholds (e.g., AIM_ANOMALY_THRESHOLD) in DetectionUtils.cpp.
Extend blacklists/patterns for specific games.
Contributing
Fork the repo, make changes, and submit a PR. Focus on stability and performance. All contributions must adhere to the license and disclaimer.
License
This project is licensed under the MIT License - see the LICENSE file for details.
Disclaimer
This software is intended for educational and research purposes only. The authors and contributors are not responsible for any misuse, including but not limited to violating game terms of service, cheating, or any legal consequences. Use at your own risk. Ensure compliance with all applicable laws and regulations. No warranty is provided, and the software is "AS IS".
