#include "fidologon/device_presence.h"

#include <windows.h>
#include <initguid.h>
#include <cfgmgr32.h>
#include <devpkey.h>

#include <vector>

#include "fidologon/errors.h"

namespace fidologon {
namespace {

// GUID_DEVINTERFACE_HID {4D1E55B2-F16F-11CF-88CB-001111000030}
constexpr GUID kHidInterface = {0x4d1e55b2, 0xf16f, 0x11cf, {0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}};

}  // namespace

bool IsHidDevicePresent(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    GUID guid = kHidInterface;
    for (int attempt = 0; attempt < 5; ++attempt) {
        ULONG length = 0;
        CONFIGRET result =
            CM_Get_Device_Interface_List_SizeW(&length, &guid, nullptr, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
        if (result != CR_SUCCESS) {
            throw Error(ErrorCode::Internal, "CM_Get_Device_Interface_List_Size failed");
        }
        std::vector<wchar_t> buffer(length + 1, L'\0');
        result = CM_Get_Device_Interface_ListW(&guid, nullptr, buffer.data(), length,
                                               CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
        if (result == CR_BUFFER_SMALL) {
            continue;  // a device arrived between the two calls
        }
        if (result != CR_SUCCESS) {
            throw Error(ErrorCode::Internal, "CM_Get_Device_Interface_List failed");
        }
        for (const wchar_t* entry = buffer.data(); *entry != L'\0'; entry += wcslen(entry) + 1) {
            if (_wcsicmp(entry, path.c_str()) == 0) {
                return true;
            }
        }
        return false;
    }
    throw Error(ErrorCode::Internal, "device list kept changing");
}

std::uint64_t HidDeviceArrivalTime(const std::wstring& path) {
    if (path.empty()) {
        return 0;
    }
    wchar_t instanceId[MAX_DEVICE_ID_LEN + 1] = {};
    DEVPROPTYPE type = DEVPROP_TYPE_EMPTY;
    ULONG size = sizeof(instanceId);
    if (CM_Get_Device_Interface_PropertyW(path.c_str(), &DEVPKEY_Device_InstanceId, &type,
                                          reinterpret_cast<PBYTE>(instanceId), &size, 0) != CR_SUCCESS ||
        type != DEVPROP_TYPE_STRING) {
        return 0;
    }
    DEVINST device = 0;
    if (CM_Locate_DevNodeW(&device, instanceId, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS) {
        return 0;  // not present
    }
    FILETIME arrival{};
    size = sizeof(arrival);
    if (CM_Get_DevNode_PropertyW(device, &DEVPKEY_Device_LastArrivalDate, &type, reinterpret_cast<PBYTE>(&arrival),
                                 &size, 0) != CR_SUCCESS ||
        type != DEVPROP_TYPE_FILETIME) {
        return 0;
    }
    return (static_cast<std::uint64_t>(arrival.dwHighDateTime) << 32) | arrival.dwLowDateTime;
}

}  // namespace fidologon
