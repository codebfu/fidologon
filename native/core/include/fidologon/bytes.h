#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace fidologon {

using Bytes = std::vector<std::uint8_t>;

// Overwrites memory in a way the optimizer cannot elide.
void SecureWipe(void* data, std::size_t size) noexcept;

void Wipe(Bytes& value) noexcept;
void Wipe(std::wstring& value) noexcept;
void Wipe(std::string& value) noexcept;

// Wipes the referenced secret when the scope ends.
template <class T>
class WipeOnExit {
public:
    explicit WipeOnExit(T& value) noexcept : value_(value) {}
    ~WipeOnExit() { Wipe(value_); }
    WipeOnExit(const WipeOnExit&) = delete;
    WipeOnExit& operator=(const WipeOnExit&) = delete;

private:
    T& value_;
};

std::string ToUtf8(std::wstring_view value);
std::wstring FromUtf8(std::string_view value);

}  // namespace fidologon
