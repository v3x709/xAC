/*
MIT License

Copyright (c) 2026 v3x709

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Disclaimer: This software is provided for educational and research purposes only. The authors are not responsible for any misuse, including but not limited to cheating in games, violation of terms of service, or any legal consequences arising from its use. Users are solely responsible for ensuring compliance with applicable laws and regulations.
*/

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <openssl/md5.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <iphlpapi.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <usbioctl.h>
#include <hidclass.h>
#include <hidpi.h>
#include <winioctl.h>
#include <ntddpci.h>
#include <d3d11.h>
#include <dxgi.h>
#include <wlanapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "hid.lib")
#pragma comment(lib, "usbd.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "wlanapi.lib")

const std::string GAME_EXE = "yourgame.exe";
const int SCAN_INTERVAL_MS = 500;
const int HEARTBEAT_INTERVAL_MS = 2500;
const int MEMORY_SCAN_DEPTH = 0x2000000;
const int SIGNATURE_SCAN_BUFFER = 0x20000;
const int BEHAVIOR_SAMPLE_WINDOW = 300;
const double AIM_ANOMALY_THRESHOLD = 0.85;
const double MOVEMENT_ANOMALY_THRESHOLD = 70.0;
const double INPUT_AUTOMATION_THRESHOLD = 0.08;
const double CV_AIMBOT_CONFIDENCE_THRESHOLD = 0.75;
const ULONG TPM_BOOT_ENTROPY_NV_INDEX = 0x01000000;
const int DMA_SCAN_DEPTH = 512;
const int FALSE_POSITIVE_ADJUSTMENT_WINDOW = 500;
const double PRO_PLAYER_THRESHOLD_MULTIPLIER = 1.5;

struct BehaviorProfile {
    std::vector<double> aimAccuracies;
    std::vector<double> movementSpeeds;
    std::vector<double> inputIntervals;
    std::vector<double> reactionTimes;
    std::vector<double> headshotRatios;
    double meanAim = 0.0;
    double stdDevAim = 0.0;
    double meanSpeed = 0.0;
    double stdDevSpeed = 0.0;
    double meanInput = 0.0;
    double stdDevInput = 0.0;
    double meanReaction = 0.0;
    double stdDevReaction = 0.0;
    double meanHeadshot = 0.0;
    double stdDevHeadshot = 0.0;
    double falsePositiveAdjustment = 1.0;
};

std::unordered_map<DWORD, BehaviorProfile> playerProfiles;

ID3D11Device* g_D3DDevice = nullptr;
ID3D11DeviceContext* g_D3DContext = nullptr;
IDXGISwapChain* g_SwapChain = nullptr;

bool checkSecureBoot() {
    try {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD secureBootEnabled;
            DWORD size = sizeof(DWORD);
            if (RegQueryValueEx(hKey, L"UEFISecureBootEnabled", NULL, NULL, (LPBYTE)&secureBootEnabled, &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return secureBootEnabled == 1;
            }
            RegCloseKey(hKey);
        }
        return false;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool verifyTPMIntegrity() {
    try {
        NTSTATUS status;
        HANDLE hTpm = INVALID_HANDLE_VALUE;
        UNICODE_STRING tpmPath = RTL_CONSTANT_STRING(L"\\Device\\Tpm");
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &tpmPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenFile(&hTpm, GENERIC_READ | GENERIC_WRITE, &objAttr, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Failed to open TPM");
        BYTE entropy[128];
        DWORD entropySize = sizeof(entropy);
        status = ZwFsControlFile(hTpm, NULL, NULL, NULL, NULL, FSCTL_TPM_GET_RANDOM, NULL, 0, entropy, entropySize);
        CloseHandle(hTpm);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Failed to get TPM entropy");
        std::string hash = calculateSHA512(entropy, entropySize);
        std::string expected = computeExpectedTPMHash(hash);
        return hash == expected;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

std::string computeExpectedTPMHash(const std::string& hash) {
    std::string systemData = getSystemSpecificDataForTPM();
    return calculateSHA512((void*)(systemData + hash).data(), systemData.size() + hash.size());
}

std::string getSystemSpecificDataForTPM() {
    std::string data = getHWIDAdvanced();
    data += std::to_string(GetTickCount64());
    return data;
}

bool detectModMenuInjection(DWORD processID) {
    try {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        if (!hProcess) throw std::runtime_error("Failed to open process for mod menu scan");
        bool detected = false;
        std::vector<BYTE> gtaPatterns = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18};
        std::vector<BYTE> robloxPatterns = {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x28, 0x53, 0x56, 0x57, 0x8B, 0xF9};
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        MEMORY_BASIC_INFORMATION mbi;
        BYTE* addr = 0;
        while (addr < si.lpMaximumApplicationAddress) {
            if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == 0) break;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                std::vector<BYTE> buffer(min(mbi.RegionSize, (SIZE_T)SIGNATURE_SCAN_BUFFER)); // Begrenzt für perf
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                    for (size_t i = 0; i < bytesRead - std::max(gtaPatterns.size(), robloxPatterns.size()); ++i) {
                        if (memcmp(&buffer[i], gtaPatterns.data(), gtaPatterns.size()) == 0 ||
                            memcmp(&buffer[i], robloxPatterns.data(), robloxPatterns.size()) == 0) {
                            detected = true;
                            break;
                        }
                    }
                }
            }
            addr += mbi.RegionSize;
        }
        CloseHandle(hProcess);
        return detected;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool detectRobloxExploit(DWORD processID) {
    try {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        if (!hProcess) throw std::runtime_error("Failed to open process for exploit scan");
        bool detected = false;
        std::vector<std::string> exploitStrings = {"SynapseX", "Krnl", "Fluxus", "ScriptWare", "JJSploit", "Electron", "Oxygen U", "ProtoSmasher"};
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        MEMORY_BASIC_INFORMATION mbi;
        BYTE* addr = 0;
        while (addr < si.lpMaximumApplicationAddress) {
            if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == 0) break;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) {
                std::vector<BYTE> buffer(min(mbi.RegionSize, (SIZE_T)SIGNATURE_SCAN_BUFFER));
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                    std::string memStr((char*)buffer.data(), bytesRead);
                    for (const auto& str : exploitStrings) {
                        if (memStr.find(str) != std::string::npos) {
                            detected = true;
                            break;
                        }
                    }
                }
            }
            addr += mbi.RegionSize;
        }
        CloseHandle(hProcess);
        return detected;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool detectSpeedHack() {
    try {
        static double lastTimeScale = 1.0;
        double currentTimeScale = getCurrentTimeScale();
        if (abs(currentTimeScale - lastTimeScale) > 0.1) return true;
        lastTimeScale = currentTimeScale;
        return false;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

double getCurrentTimeScale() {
    static LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(5);
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - start.QuadPart) / (freq.QuadPart / 200.0);
}

void logError(const std::string& error) {
    HANDLE hFile = CreateFile(L"anticheat_log.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_END);
        std::string encrypted = xorEncrypt(error); // Simple obfuscation for logs
        WriteFile(hFile, encrypted.c_str(), encrypted.size(), NULL, NULL);
        WriteFile(hFile, "\n", 1, NULL, NULL);
        CloseHandle(hFile);
    }
}

std::string xorEncrypt(const std::string& data) {
    std::string encrypted = data;
    char key = 0x5A; // Simple XOR key for obfuscation
    for (char& c : encrypted) c ^= key;
    return encrypted;
}

bool isDebuggerPresentAdvanced() {
    try {
        if (IsDebuggerPresent()) return true;
        PPEB peb = (PPEB)__readfsdword(0x30);
        if (peb->BeingDebugged) return true;
        if (peb->NtGlobalFlag & 0x70) return true;
        HANDLE hProcess = GetCurrentProcess();
        BOOL checkRemote = FALSE;
        CheckRemoteDebuggerPresent(hProcess, &checkRemote);
        if (checkRemote) return true;
        CONTEXT ctx;
        RtlCaptureContext(&ctx);
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) return true;
        __try {
            RaiseException(DBG_CONTROL_C, 0, 0, NULL);
            return false;
        } __except (GetExceptionCode() == DBG_CONTROL_C ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool detectTimingAttacks() {
    try {
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        for (volatile int i = 0; i < 5000; ++i);
        QueryPerformanceCounter(&end);
        LONGLONG elapsed = end.QuadPart - start.QuadPart;
        LONGLONG expected = freq.QuadPart / 200000;
        if (abs(elapsed - expected) > expected / 20) return true;
        DWORD startTick = GetTickCount64();
        Sleep(15);
        DWORD endTick = GetTickCount64();
        if (endTick - startTick < 13 || endTick - startTick > 17) return true;
        return false;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool detectVirtualEnvironment() {
    try {
        std::string manu = getSystemManufacturer();
        std::transform(manu.begin(), manu.end(), manu.begin(), ::tolower);
        if (manu.find("vmware") != std::string::npos || manu.find("virtualbox") != std::string::npos || manu.find("qemu") != std::string::npos || manu.find("xen") != std::string::npos || manu.find("parallels") != std::string::npos || manu.find("hyper-v") != std::string::npos) return true;
        if (isRegistryKeyPresent(L"HARDWARE\\ACPI\\DSDT\\VBOX__")) return true;
        if (isRegistryKeyPresent(L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", L"Storage#Volume#{GUID}#00000000")) return true;
        return false;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

std::string getSystemManufacturer() {
    char manufacturer[256];
    DWORD size = sizeof(manufacturer);
    if (GetComputerNameA(manufacturer, &size)) return manufacturer;
    return "";
}

bool isRegistryKeyPresent(const std::wstring& keyPath, const std::wstring& valueName = L"") {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        if (!valueName.empty()) {
            DWORD type, size = 0;
            result = RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, NULL, &size);
        }
        RegCloseKey(hKey);
        return result == ERROR_SUCCESS;
    }
    return false;
}

bool detectKernelDebugger() {
    try {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION kdInfo;
        NTSTATUS status = ZwQuerySystemInformation(SystemKernelDebuggerInformation, &kdInfo, sizeof(kdInfo), NULL);
        if (NT_SUCCESS(status) && (kdInfo.KernelDebuggerEnabled || !kdInfo.KernelDebuggerNotPresent)) return true;
        return false;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool detectHypervisor() {
    try {
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        if ((cpuInfo[2] & (1 << 31)) != 0) return true;
        __cpuidex(cpuInfo, 0x40000000, 0);
        char hvVendor[13] = {0};
        memcpy(hvVendor, &cpuInfo[1], 12);
        std::string vendor = hvVendor;
        if (vendor.find("Microsoft Hv") != std::string::npos || vendor.find("VMware") != std::string::npos || vendor.find("KVM") != std::string::npos || vendor.find("VBox") != std::string::npos || vendor.find("prl hyperv") != std::string::npos || vendor.find("XenVMM") != std::string::npos) return true;
        return false;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool detectHardwareCheats() {
    try {
        HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_MOUSE, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (hDevInfo == INVALID_HANDLE_VALUE) return false;
        SP_DEVICE_INTERFACE_DATA interfaceData = {sizeof(SP_DEVICE_INTERFACE_DATA)};
        bool suspicious = false;
        for (DWORD i = 0; SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &GUID_DEVCLASS_MOUSE, i, &interfaceData); ++i) {
            DWORD requiredSize = 0;
            SetupDiGetDeviceInterfaceDetail(hDevInfo, &interfaceData, NULL, 0, &requiredSize, NULL);
            PSP_DEVICE_INTERFACE_DETAIL_DATA detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(requiredSize);
            detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
            if (SetupDiGetDeviceInterfaceDetail(hDevInfo, &interfaceData, detailData, requiredSize, NULL, NULL)) {
                HANDLE hDevice = CreateFile(detailData->DevicePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                if (hDevice != INVALID_HANDLE_VALUE) {
                    HIDP_CAPS caps;
                    PHIDP_PREPARSED_DATA preparsedData;
                    if (HidD_GetPreparsedData(hDevice, &preparsedData)) {
                        HidP_GetCaps(preparsedData, &caps);
                        if (caps.NumberInputValueCaps > 150 || caps.NumberInputButtonCaps > 40) suspicious = true;
                        HidD_FreePreparsedData(preparsedData);
                    }
                    CloseHandle(hDevice);
                }
            }
            free(detailData);
            if (suspicious) break;
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);
        return suspicious;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool detectDMACheats() {
    try {
        HANDLE hPci = CreateFile(L"\\Device\\Pci", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hPci == INVALID_HANDLE_VALUE) return false;
        bool detected = false;
        BYTE buffer[DMA_SCAN_DEPTH];
        DWORD bytesReturned;
        for (int bus = 0; bus < 128; ++bus) {
            for (int device = 0; device < 16; ++device) {
                for (int func = 0; func < 4; ++func) {
                    ULONG pciAddr = (bus << 8) | (device << 3) | func;
                    if (!DeviceIoControl(hPci, IOCTL_READ_PCI_CONFIG, &pciAddr, sizeof(ULONG), buffer, DMA_SCAN_DEPTH, &bytesReturned, NULL)) continue;
                    std::string pciData((char*)buffer, bytesReturned);
                    if (isSuspiciousPCIData(pciData)) {
                        detected = true;
                        break;
                    }
                }
                if (detected) break;
            }
            if (detected) break;
        }
        CloseHandle(hPci);
        return detected;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool isSuspiciousPCIData(const std::string& data) {
    std::vector<std::string> suspiciousPatterns = {"DMA Cheat", "External Hack", "PCIe Injector", "Thunderbolt Cheat"};
    for (const auto& pattern : suspiciousPatterns) {
        if (data.find(pattern) != std::string::npos) return true;
    }
    return false;
}

bool scanForAnomalousModules(DWORD processID) {
    try {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        if (!hProcess) throw std::runtime_error("Failed to open process");
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) throw std::runtime_error("Failed to enum modules");
        bool anomalous = false;
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                std::string modPath = szModName;
                if (!isModuleLegitimate(modPath)) {
                    anomalous = true;
                    break;
                }
            }
        }
        CloseHandle(hProcess);
        return anomalous;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool isModuleLegitimate(const std::string& modPath) {
    std::string hash = calculateSHA256(modPath.data(), modPath.size());
    std::vector<std::string> knownLegitHashes = getKnownLegitModuleHashes();
    return std::find(knownLegitHashes.begin(), knownLegitHashes.end(), hash) != knownLegitHashes.end() && verifyDriverSignature(std::wstring(modPath.begin(), modPath.end()));
}

std::vector<std::string> getKnownLegitModuleHashes() {
    std::vector<std::string> hashes;
    hashes.push_back(calculateSHA256((void*)"kernel32.dll", strlen("kernel32.dll")));
    hashes.push_back(calculateSHA256((void*)"user32.dll", strlen("user32.dll")));
    hashes.push_back(calculateSHA256((void*)"advapi32.dll", strlen("advapi32.dll")));
    return hashes;
}

bool selfIntegrityCheck() {
    try {
        HMODULE hModule = GetModuleHandle(NULL);
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
        size_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        std::string currentHash = calculateSHA512(hModule, imageSize);
        std::string expectedHash = computeExpectedSelfHashAtRuntime(currentHash);
        return currentHash == expectedHash;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

std::string computeExpectedSelfHashAtRuntime(const std::string& current) {
    std::string selfData = getSelfModuleData();
    return calculateSHA512((void*)(selfData + current).data(), selfData.size() + current.size());
}

std::string getSelfModuleData() {
    std::string data;
    try {
        HANDLE hProcess = GetCurrentProcess();
        MODULEINFO modInfo;
        if (!GetModuleInformation(hProcess, GetModuleHandle(NULL), &modInfo, sizeof(modInfo))) throw std::runtime_error("Failed to get self module info");
        data.assign((char*)modInfo.lpBaseOfDll, modInfo.SizeOfImage);
    } catch (const std::exception& e) {
        logError(e.what());
    }
    return data;
}

bool verifyDriverSignature(const std::wstring& driverPath) {
    try {
        WINTRUST_FILE_INFO fileInfo = {sizeof(WINTRUST_FILE_INFO), driverPath.c_str(), NULL, NULL};
        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA winTrustData = {sizeof(WINTRUST_DATA), NULL, NULL, WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE, &fileInfo, WTD_STATEACTION_VERIFY, NULL, NULL, WTD_CACHE_ONLY_URL_RETRIEVAL};
        LONG status = WinVerifyTrust(NULL, &policyGUID, &winTrustData);
        return status == ERROR_SUCCESS;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool scanForUnsignedDrivers() {
    try {
        LPVOID drivers[1024];
        DWORD cbNeeded;
        if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) throw std::runtime_error("Failed to enum drivers");
        int driverCount = cbNeeded / sizeof(drivers[0]);
        for (int i = 0; i < driverCount; i++) {
            WCHAR driverPath[MAX_PATH];
            if (GetDeviceDriverFileName(drivers[i], driverPath, MAX_PATH)) {
                if (!verifyDriverSignature(driverPath)) {
                    return true;
                }
            }
        }
        return false;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

std::string getHWIDAdvanced() {
    std::string hwid;
    try {
        PIP_ADAPTER_INFO pAdapterInfo = getAdapterInfo();
        hwid += std::string((char*)pAdapterInfo->Address, pAdapterInfo->AddressLength);
        free(pAdapterInfo);
        HW_PROFILE_INFO hwProfileInfo;
        if (!GetCurrentHwProfile(&hwProfileInfo)) throw std::runtime_error("Failed to get HW profile");
        char guidAnsi[256];
        wcstombs(guidAnsi, hwProfileInfo.szHwProfileGuid, 256);
        hwid += guidAnsi;
        hwid += getCPUInfo();
        hwid += getTokenLUID();
        hwid += getDiskSerial();
        hwid += getBIOSUUID();
        return calculateSHA512(hwid.data(), hwid.size());
    } catch (const std::exception& e) {
        logError(e.what());
        return "";
    }
}

PIP_ADAPTER_INFO getAdapterInfo() {
    ULONG bufferSize = 0;
    GetAdaptersInfo(NULL, &bufferSize);
    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(bufferSize);
    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) != ERROR_SUCCESS) {
        free(pAdapterInfo);
        pAdapterInfo = nullptr;
    }
    return pAdapterInfo;
}

std::string getCPUInfo() {
    std::string cpuInfo;
    int cpuData[4];
    __cpuid(cpuData, 0x80000002);
    cpuInfo += std::string((char*)cpuData, 16);
    __cpuid(cpuData, 0x80000003);
    cpuInfo += std::string((char*)cpuData, 16);
    __cpuid(cpuData, 0x80000004);
    cpuInfo += std::string((char*)cpuData, 16);
    return cpuInfo;
}

std::string getTokenLUID() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return "";
    DWORD len;
    GetTokenInformation(hToken, TokenStatistics, NULL, 0, &len);
    PTOKEN_STATISTICS stats = (PTOKEN_STATISTICS)malloc(len);
    if (!GetTokenInformation(hToken, TokenStatistics, stats, len, &len)) {
        free(stats);
        CloseHandle(hToken);
        return "";
    }
    char luidStr[32];
    sprintf(luidStr, "%llu", stats->AuthenticationId.QuadPart);
    std::string luid = luidStr;
    free(stats);
    CloseHandle(hToken);
    return luid;
}

std::string getDiskSerial() {
    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) {
        return std::to_string(serial);
    }
    return "";
}

std::string getBIOSUUID() {
    std::string uuid;
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR biosUUID[256];
        DWORD size = sizeof(biosUUID);
        if (RegQueryValueEx(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)biosUUID, &size) == ERROR_SUCCESS) {
            char uuidAnsi[256];
            wcstombs(uuidAnsi, biosUUID, 256);
            uuid = uuidAnsi;
        }
        RegCloseKey(hKey);
    }
    return uuid;
}