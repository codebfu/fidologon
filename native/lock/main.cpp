// Locks the interactive session it runs in. The service starts it inside the
// user's session because LockWorkStation only works from that session.

#include <windows.h>

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) { return LockWorkStation() ? 0 : static_cast<int>(GetLastError()); }
