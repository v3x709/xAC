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

#include <ntddk.h>
#include <ntifs.h>
#include <etw.h> // Für ETW

HANDLE g_EtwEventHandle = nullptr;
PDEVICE_OBJECT g_DeviceObject = nullptr;
std::string g_EventBuffer; // Simple buffer for events (minimal)

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    switch (irpStack->MajorFunction) {
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            break;
        case IRP_MJ_DEVICE_CONTROL:
            if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_EVENT_DATA) {
                RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_EventBuffer.data(), min(g_EventBuffer.size(), irpStack->Parameters.DeviceIoControl.OutputBufferLength));
                Irp->IoStatus.Information = g_EventBuffer.size();
                g_EventBuffer.clear(); // Clear after send
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

void initETWMonitoring() {
    EVENT_TRACE_PROPERTIES props = {0};
    props.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES);
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    GUID sessionGuid;
    RtlGUIDFromString(&sessionGuid, L"{GUID}");
    StartTrace(&g_EtwEventHandle, L"AntiCheatSession", &props);
    EnableTraceEx2(g_EtwEventHandle, &EVENT_TRACE_SYSTEM_EVENT_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
}

void OnProcessCreate(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (CreateInfo && CreateInfo->ImageFileName) {
        std::wstring imageName(CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length / sizeof(WCHAR));
        std::string imgName(imageName.begin(), imageName.end());
        g_EventBuffer += imgName + ";"; // Append to buffer for user-mode
    }
}

OB_PREOP_CALLBACK_STATUS PreHandleOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInfo) {
    if (OperationInfo->ObjectType == *PsProcessType && (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE || OperationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)) {
        ACCESS_MASK& desiredAccess = OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;
        desiredAccess &= \~(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION);
        g_EventBuffer += "HandleOp;"; // Log event
    }
    return OB_PREOP_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
    PsRemoveCreateProcessNotifyRoutineEx(OnProcessCreate);
    if (g_ObHandle) ObUnRegisterCallbacks(g_ObHandle);
    if (g_EtwEventHandle) StopTrace(g_EtwEventHandle, L"AntiCheatSession", NULL);
    IoDeleteSymbolicLink(&RTL_CONSTANT_STRING(L"\\DosDevices\\UltimateAntiCheat"));
    IoDeleteDevice(g_DeviceObject);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;

    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(OnProcessCreate, FALSE);
    if (!NT_SUCCESS(status)) return status;

    OB_OPERATION_REGISTRATION opReg;
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = PreHandleOperation;
    opReg.PostOperation = NULL;

    OB_CALLBACK_REGISTRATION cbReg;
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    RtlInitUnicodeString(&cbReg.Altitude, L"400000");
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = &opReg;

    status = ObRegisterCallbacks(&cbReg, &g_ObHandle);
    if (!NT_SUCCESS(status)) {
        PsRemoveCreateProcessNotifyRoutineEx(OnProcessCreate);
        return status;
    }

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\UltimateAntiCheat");
    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\UltimateAntiCheat");
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    initETWMonitoring();

    return STATUS_SUCCESS;
}