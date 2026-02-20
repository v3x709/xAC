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

#include <opencv2/opencv.hpp>
#include <tensorflow/lite/interpreter.h>
#include <tensorflow/lite/kernels/register.h>
#include <tensorflow/lite/model.h>

#pragma comment(lib, "opencv_world.lib")
#pragma comment(lib, "tensorflowlite.lib")

std::unique_ptr<tflite::FlatBufferModel> mlBehaviorModel;
std::unique_ptr<tflite::Interpreter> mlBehaviorInterpreter;
std::unique_ptr<tflite::FlatBufferModel> mlMemoryModel;
std::unique_ptr<tflite::Interpreter> mlMemoryInterpreter;
cv::Ptr<cv::ml::SVM> svmMemoryClassifier;

bool useML = true; // Flag for fallback

void initMLModels() {
    try {
        mlBehaviorModel = tflite::FlatBufferModel::BuildFromBuffer(getBehaviorModelBuffer(), getBehaviorModelSize());
        tflite::ops::builtin::BuiltinOpResolver resolver;
        tflite::InterpreterBuilder behaviorBuilder(*mlBehaviorModel, resolver)(&mlBehaviorInterpreter);
        if (mlBehaviorInterpreter->AllocateTensors() != kTfLiteOk) throw std::runtime_error("Behavior alloc failed");

        mlMemoryModel = tflite::FlatBufferModel::BuildFromBuffer(getMemoryModelBuffer(), getMemoryModelSize());
        tflite::InterpreterBuilder memoryBuilder(*mlMemoryModel, resolver)(&mlMemoryInterpreter);
        if (mlMemoryInterpreter->AllocateTensors() != kTfLiteOk) throw std::runtime_error("Memory alloc failed");

        svmMemoryClassifier = cv::ml::SVM::create();
        svmMemoryClassifier->setType(cv::ml::SVM::C_SVC);
        svmMemoryClassifier->setKernel(cv::ml::SVM::RBF);
        cv::Mat trainData = getDynamicTrainData();
        cv::Mat labels = getDynamicLabels();
        svmMemoryClassifier->train(trainData, cv::ml::ROW_SAMPLE, labels);
    } catch (const std::exception& e) {
        logError(e.what());
        useML = false; // Fallback to heuristics
    }
}

bool analyzeMemoryWithML(const cv::Mat& memFeatures) {
    if (!useML) return heuristicMemoryCheck(memFeatures);
    try {
        float* input = mlMemoryInterpreter->typed_input_tensor<float>(0);
        memFeatures.copyTo(cv::Mat(1, memFeatures.cols, CV_32F, input));
        if (mlMemoryInterpreter->Invoke() != kTfLiteOk) throw std::runtime_error("ML invoke failed");
        float* output = mlMemoryInterpreter->typed_output_tensor<float>(0);
        return *output > 0.8;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool heuristicMemoryCheck(const cv::Mat& memFeatures) {
    // Fallback: Simple threshold on feature sum
    double sum = cv::sum(memFeatures)[0];
    return sum > 1000.0; // Example threshold
}

void extractMemoryFeatures(const cv::Mat& memData, cv::Mat& features) {
    cv::Ptr<cv::Feature2D> orb = cv::ORB::create(500, 1.2f, 8, 31, 0, 2, cv::ORB::HARRIS_SCORE, 31, 20);
    std::vector<cv::KeyPoint> keypoints;
    cv::Mat descriptors;
    orb->detectAndCompute(memData, cv::noArray(), keypoints, descriptors);
    features = descriptors.reshape(1, 1);
}

bool scanMemoryForDynamicSignatures(HANDLE hProcess) {
    try {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        MEMORY_BASIC_INFORMATION mbi;
        BYTE* addr = 0;
        bool found = false;
        while (addr < si.lpMaximumApplicationAddress) {
            if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == 0) break;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    cv::Mat memImage(1, bytesRead, CV_8UC1, buffer.data());
                    cv::Mat features;
                    extractMemoryFeatures(memImage, features);
                    if (analyzeMemoryWithML(features) || svmMemoryClassifier->predict(features) > 0.7) found = true;
                }
            }
            addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        }
        return found;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool deepMemoryScanWithML(DWORD processID) {
    try {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        if (!hProcess) throw std::runtime_error("Failed to open process for memory scan");
        bool cheatFound = scanMemoryForDynamicSignatures(hProcess);
        CloseHandle(hProcess);
        return cheatFound;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool analyzeBehaviorWithML(const std::vector<float>& inputData) {
    if (!useML) return heuristicBehaviorCheck(inputData);
    try {
        float* input = mlBehaviorInterpreter->typed_input_tensor<float>(0);
        std::copy(inputData.begin(), inputData.end(), input);
        if (mlBehaviorInterpreter->Invoke() != kTfLiteOk) throw std::runtime_error("Behavior ML invoke failed");
        float* output = mlBehaviorInterpreter->typed_output_tensor<float>(0);
        return *output > 0.7;
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

bool heuristicBehaviorCheck(const std::vector<float>& features) {
    // Fallback: Simple average > threshold
    float avg = std::accumulate(features.begin(), features.end(), 0.0f) / features.size();
    return avg > 3.0f; // Example
}

void updateBehaviorProfile(DWORD playerId, double aimAccuracy, double movementSpeed, double inputInterval, double reactionTime, double headshotRatio) {
    auto& profile = playerProfiles[playerId];
    profile.aimAccuracies.push_back(aimAccuracy);
    profile.movementSpeeds.push_back(movementSpeed);
    profile.inputIntervals.push_back(inputInterval);
    profile.reactionTimes.push_back(reactionTime);
    profile.headshotRatios.push_back(headshotRatio);
    if (profile.aimAccuracies.size() > BEHAVIOR_SAMPLE_WINDOW) {
        profile.aimAccuracies.erase(profile.aimAccuracies.begin());
        profile.movementSpeeds.erase(profile.movementSpeeds.begin());
        profile.inputIntervals.erase(profile.inputIntervals.begin());
        profile.reactionTimes.erase(profile.reactionTimes.begin());
        profile.headshotRatios.erase(profile.headshotRatios.begin());
    }
    int n = profile.aimAccuracies.size();
    double sumAim = std::accumulate(profile.aimAccuracies.begin(), profile.aimAccuracies.end(), 0.0);
    double sumSqAim = std::inner_product(profile.aimAccuracies.begin(), profile.aimAccuracies.end(), profile.aimAccuracies.begin(), 0.0);
    double sumSpeed = std::accumulate(profile.movementSpeeds.begin(), profile.movementSpeeds.end(), 0.0);
    double sumSqSpeed = std::inner_product(profile.movementSpeeds.begin(), profile.movementSpeeds.end(), profile.movementSpeeds.begin(), 0.0);
    double sumInput = std::accumulate(profile.inputIntervals.begin(), profile.inputIntervals.end(), 0.0);
    double sumSqInput = std::inner_product(profile.inputIntervals.begin(), profile.inputIntervals.end(), profile.inputIntervals.begin(), 0.0);
    double sumReaction = std::accumulate(profile.reactionTimes.begin(), profile.reactionTimes.end(), 0.0);
    double sumSqReaction = std::inner_product(profile.reactionTimes.begin(), profile.reactionTimes.end(), profile.reactionTimes.begin(), 0.0);
    double sumHeadshot = std::accumulate(profile.headshotRatios.begin(), profile.headshotRatios.end(), 0.0);
    double sumSqHeadshot = std::inner_product(profile.headshotRatios.begin(), profile.headshotRatios.end(), profile.headshotRatios.begin(), 0.0);
    profile.meanAim = sumAim / n;
    profile.stdDevAim = sqrt((sumSqAim / n) - (profile.meanAim * profile.meanAim));
    profile.meanSpeed = sumSpeed / n;
    profile.stdDevSpeed = sqrt((sumSqSpeed / n) - (profile.meanSpeed * profile.meanSpeed));
    profile.meanInput = sumInput / n;
    profile.stdDevInput = sqrt((sumSqInput / n) - (profile.meanInput * profile.meanInput));
    profile.meanReaction = sumReaction / n;
    profile.stdDevReaction = sqrt((sumSqReaction / n) - (profile.meanReaction * profile.meanReaction));
    profile.meanHeadshot = sumHeadshot / n;
    profile.stdDevHeadshot = sqrt((sumSqHeadshot / n) - (profile.meanHeadshot * profile.meanHeadshot));
    if (n > FALSE_POSITIVE_ADJUSTMENT_WINDOW && profile.meanAim > AIM_ANOMALY_THRESHOLD * PRO_PLAYER_THRESHOLD_MULTIPLIER) {
        profile.falsePositiveAdjustment *= 1.1;
    }
}

bool detectBehaviorAnomaly(DWORD playerId) {
    auto& profile = playerProfiles[playerId];
    if (profile.aimAccuracies.empty()) return false;
    double recentAim = profile.aimAccuracies.back();
    double recentSpeed = profile.movementSpeeds.back();
    double recentInput = profile.inputIntervals.back();
    double recentReaction = profile.reactionTimes.back();
    double recentHeadshot = profile.headshotRatios.back();
    double zAim = (recentAim - profile.meanAim) / (profile.stdDevAim + 1e-8) / profile.falsePositiveAdjustment;
    double zSpeed = (recentSpeed - profile.meanSpeed) / (profile.stdDevSpeed + 1e-8);
    double zInput = (recentInput - profile.meanInput) / (profile.stdDevInput + 1e-8);
    double zReaction = (recentReaction - profile.meanReaction) / (profile.stdDevReaction + 1e-8);
    double zHeadshot = (recentHeadshot - profile.meanHeadshot) / (profile.stdDevHeadshot + 1e-8) / profile.falsePositiveAdjustment;
    std::vector<float> features = {static_cast<float>(zAim), static_cast<float>(zSpeed), static_cast<float>(zInput), static_cast<float>(zReaction), static_cast<float>(zHeadshot)};
    return analyzeBehaviorWithML(features) || std::any_of(features.begin(), features.end(), [](float z){ return abs(z) > 4.0; });
}

bool detectCVAimbot() {
    try {
        if (!g_D3DDevice) return false;
        ID3D11Texture2D* backBuffer = nullptr;
        HRESULT hr = g_SwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&backBuffer);
        if (FAILED(hr)) return false;
        D3D11_TEXTURE2D_DESC desc;
        backBuffer->GetDesc(&desc);
        std::vector<BYTE> screenData(desc.Width * desc.Height * 4);
        D3D11_MAPPED_SUBRESOURCE mapped;
        hr = g_D3DContext->Map(backBuffer, 0, D3D11_MAP_READ, 0, &mapped);
        if (FAILED(hr)) {
            backBuffer->Release();
            return false;
        }
        memcpy(screenData.data(), mapped.pData, screenData.size());
        g_D3DContext->Unmap(backBuffer, 0);
        backBuffer->Release();
        cv::Mat screen(desc.Height, desc.Width, CV_8UC4, screenData.data());
        cv::Mat gray;
        cv::cvtColor(screen, gray, cv::COLOR_RGBA2GRAY);
        cv::Mat edges;
        cv::Canny(gray, edges, 40, 160);
        std::vector<std::vector<cv::Point>> contours;
        cv::findContours(edges, contours, cv::RETR_TREE, cv::CHAIN_APPROX_TC89_KCOS);
        double anomalyScore = 0.0;
        int count = 0;
        for (const auto& contour : contours) {
            cv::Rect bound = cv::boundingRect(contour);
            if (bound.width > 15 && bound.height > 15) {
                cv::Mat roi = gray(bound);
                anomalyScore += computeCVAnomaly(roi);
                count++;
            }
        }
        return (count > 0) && (anomalyScore / count > CV_AIMBOT_CONFIDENCE_THRESHOLD);
    } catch (const std::exception& e) {
        logError(e.what());
        return false;
    }
}

double computeCVAnomaly(const cv::Mat& roi) {
    cv::Ptr<cv::ml::SVM> svmCV = cv::ml::SVM::create();
    svmCV->load("cv_aimbot_model.xml");
    cv::Mat features;
    extractCVFeatures(roi, features);
    return svmCV->predict(features, cv::noArray(), cv::ml::SVM::RAW_OUTPUT);
}

void extractCVFeatures(const cv::Mat& roi, cv::Mat& features) {
    cv::HOGDescriptor hog(cv::Size(64,64), cv::Size(16,16), cv::Size(8,8), cv::Size(8,8), 9);
    std::vector<float> descriptors;
    hog.compute(roi, descriptors);
    features = cv::Mat(1, descriptors.size(), CV_32F, descriptors.data());
}