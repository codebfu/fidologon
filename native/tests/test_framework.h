#pragma once

// Minimal self-registering test framework (no external dependency).

#include <exception>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace fltest {

struct TestCase {
    const char* name;
    void (*body)();
};

std::vector<TestCase>& Registry();

class Failure : public std::exception {
public:
    Failure(const char* file, int line, const std::string& message) {
        std::ostringstream text;
        text << file << "(" << line << "): " << message;
        what_ = text.str();
    }
    const char* what() const noexcept override { return what_.c_str(); }

private:
    std::string what_;
};

struct Registrar {
    Registrar(const char* name, void (*body)()) { Registry().push_back({name, body}); }
};

// Per-run registry root under HKCU, removed when the test run ends.
const std::wstring& TestStorageRoot();
void ResetTestStorage();

}  // namespace fltest

#define TEST(name)                                                  \
    static void name();                                             \
    static const fltest::Registrar name##_registrar(#name, &name);  \
    static void name()

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            throw fltest::Failure(__FILE__, __LINE__, "CHECK(" #condition ")"); \
        }                                                                       \
    } while (0)

#define CHECK_EQ(actual, expected)                                                                     \
    do {                                                                                               \
        if (!((actual) == (expected))) {                                                               \
            throw fltest::Failure(__FILE__, __LINE__, "CHECK_EQ(" #actual ", " #expected ") failed"); \
        }                                                                                              \
    } while (0)

#define CHECK_THROWS_CODE(expression, expectedCode)                                                    \
    do {                                                                                               \
        bool thrown_ = false;                                                                          \
        try {                                                                                          \
            expression;                                                                                \
        } catch (const fidologon::Error& e_) {                                                         \
            thrown_ = true;                                                                            \
            if (e_.code() != (expectedCode)) {                                                         \
                throw fltest::Failure(__FILE__, __LINE__,                                              \
                                      std::string("unexpected error code for " #expression ": ") +     \
                                          e_.what());                                                  \
            }                                                                                          \
        }                                                                                              \
        if (!thrown_) {                                                                                \
            throw fltest::Failure(__FILE__, __LINE__, "expected " #expression " to throw");            \
        }                                                                                              \
    } while (0)
