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

#include "DetectionUtils.h"
#include "MLProcessing.h"
#include "KernelDriver.h"

HANDLE g_DriverHandle = INVALID_HANDLE_VALUE;

void initDriverCommunication() {
    g_DriverHandle = CreateFile(L"\\\\.\\UltimateAntiCheat", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_DriverHandle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Failed to open driver");
    }
}

std::string getEventDataFromDriver() {
    std::string eventData;
    DWORD bytesReturned;
    char buffer[1024];
    if (DeviceIoControl(g_DriverHandle, IOCTL_GET_EVENT_DATA, NULL, 0, buffer, sizeof(buffer), &bytesReturned, NULL)) {
        eventData.assign(buffer, bytesReturned);
    }
    return eventData;
}

int main() {
    try {
        if (!checkSecureBoot() || !verifyTPMIntegrity()) {
            return 1;
        }

        SERVICE_TABLE_ENTRY serviceTable[] = {
            { (LPSTR)"UltimateAntiCheat", (LPSERVICE_MAIN_FUNCTION)DriverEntry },
            { NULL, NULL }
        };
        if (!StartServiceCtrlDispatcher(serviceTable)) throw std::runtime_error("Failed to start service dispatcher");

        initDriverCommunication();
        initMLModels(); // Optional, with fallback

        HANDLE hThread = CreateThread(NULL, 0, AntiCheatHeartbeat, NULL, 0, NULL);
        if (!hThread) throw std::runtime_error("Failed to create heartbeat thread");
        SetThreadPriority(hThread, THREAD_PRIORITY_BELOW_NORMAL);

        while (true) {
            Sleep(4000);
        }
    } catch (const std::exception& e) {
        logError(e.what());
        return 1;
    }

    return 0;
}

DWORD WINAPI AntiCheatHeartbeat(LPVOID param) {
    while (true) {
        try {
            std::string eventData = getEventDataFromDriver();
            if (!eventData.empty() && isSuspiciousEvent(eventData)) {
                DWORD gamePid = getGameProcessID();
                if (gamePid) {
                    if (scanForAnomalousModules(gamePid) || deepMemoryScanWithML(gamePid) || detectModMenuInjection(gamePid) || 
                        detectRobloxExploit(gamePid) || detectCVAimbot()) {
                        terminateGameProcess(gamePid);
                    }
                    BehaviorData data = fetchGameBehaviorData(gamePid);
                    updateBehaviorProfile(gamePid, data.aimAccuracy, data.movementSpeed, data.inputInterval, data.reactionTime, data.headshotRatio);
                    if (detectBehaviorAnomaly(gamePid)) {
                        terminateGameProcess(gamePid);
                    }
                    sendToServerForValidation(getHWIDAdvanced(), data);
                }
            }
            // Einmalige Checks am Start, event-triggered danach
        } catch (const std::exception& e) {
            logError(e.what());
        }

        Sleep(HEARTBEAT_INTERVAL_MS + (rand() % 1000));
    }
    return 0;
}

bool isSuspiciousEvent(const std::string& eventData) {
    // Heuristik: Check for 'inject' or 'cheat' in event data
    return eventData.find("inject") != std::string::npos || eventData.find("cheat") != std::string::npos;
}

void sendToServerForValidation(const std::string& hwid, const BehaviorData& data) {
    try {
        HANDLE hSocket = createSecureSocket();
        if (hSocket != INVALID_HANDLE_VALUE) {
            // Challenge-Response
            char nonce[32];
            int recvLen = recv((SOCKET)hSocket, nonce, 32, 0);
            if (recvLen > 0) {
                std::string challengeResponse = calculateSHA256((void*)(hwid + std::string(nonce, recvLen) + std::to_string(data.aimAccuracy)).data(), hwid.size() + recvLen + sizeof(double));
                send((SOCKET)hSocket, challengeResponse.c_str(), challengeResponse.size(), 0);
                char response[1024];
                recvLen = recv((SOCKET)hSocket, response, 1024, 0);
                if (recvLen > 0 && std::string(response, recvLen).find("INVALID") != std::string::npos) {
                    ExitProcess(0xDEADBEEF);
                }
            }
            closesocket((SOCKET)hSocket);
        }
    } catch (const std::exception& e) {
        logError(e.what());
    }
}