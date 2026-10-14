#include "fidologon/authenticator.h"

#include <mutex>

namespace fidologon {
namespace {

std::mutex g_mutex;
std::shared_ptr<Authenticator> g_current;

}  // namespace

std::shared_ptr<Authenticator> GetAuthenticator() {
    std::lock_guard lock(g_mutex);
    if (!g_current) {
        g_current = CreateFido2Authenticator();
    }
    return g_current;
}

#ifdef FIDOLOGON_TESTING
void ReplaceAuthenticatorForTests(std::shared_ptr<Authenticator> authenticator) {
    std::lock_guard lock(g_mutex);
    g_current = std::move(authenticator);
}
#endif

}  // namespace fidologon
