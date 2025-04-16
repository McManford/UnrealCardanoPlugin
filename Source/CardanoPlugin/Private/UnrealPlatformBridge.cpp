#include "UnrealPlatformBridge.h"
#include "Misc/DateTime.h"
#include "HAL/PlatformProcess.h"

extern "C" {
    uint64_t UnrealGetUnixTimestamp()
    {
        return FDateTime::UtcNow().ToUnixTimestamp();
    }

    void UnrealSleep(float Seconds)
    {
        FPlatformProcess::Sleep(Seconds);
    }
}