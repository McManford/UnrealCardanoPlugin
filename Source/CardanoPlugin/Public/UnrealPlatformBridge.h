#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	uint64_t UnrealGetUnixTimestamp();
	void UnrealSleep(float Seconds);

#ifdef __cplusplus
}
#endif