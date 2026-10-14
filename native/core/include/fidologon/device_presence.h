#pragma once

#include <cstdint>
#include <string>

namespace fidologon {

// True when a HID device interface with this path is currently present.
// Paths returned by libfido2 on Windows are HID device interface paths.
bool IsHidDevicePresent(const std::wstring& path);

// When Windows last saw the device behind this HID interface arrive (FILETIME), or 0 when the
// interface is absent or the time is unknown. A key unplugged and plugged back gets a new
// arrival time even when it keeps the same path (keys without a USB serial number get a path
// derived from the USB port), so it tells a replugged or swapped key from the one that stayed.
std::uint64_t HidDeviceArrivalTime(const std::wstring& path);

}  // namespace fidologon
