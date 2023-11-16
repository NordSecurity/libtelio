// Workaround for wireguard-go hanging indefinitely, when building with MSVC.
//
// Since Go does not support the MSVC toolchain, the static Go runtime initializer function
// is created according to the GNU libc format and will be stored in a ".ctors"
// image section, which the MSVC runtime knows nothing about. In order to overcome this,
// we need to call this initializer function separately before calling any Go code.

#if defined(_MSC_VER)

#include <windows.h>

#ifdef _M_IX86
#define RT0_CPUARCH_WINDOWS_LIB _rt0_386_windows_lib
#elif _M_AMD64
#define RT0_CPUARCH_WINDOWS_LIB _rt0_amd64_windows_lib
#elif _M_ARM
#define RT0_CPUARCH_WINDOWS_LIB _rt0_arm_windows_lib
#elif (_M_ARM64 || _M_ARM64EC)
#define RT0_CPUARCH_WINDOWS_LIB _rt0_arm64_windows_lib
#else
#error "Unsupported CPU architecture"
#endif
extern void __cdecl RT0_CPUARCH_WINDOWS_LIB(void);

#define INIT_NONE 0
#define INIT_DOING 1
#define INIT_DONE 2
static volatile LONG s_GoRuntimeInitialized = INIT_NONE;

void CallWindowsStaticGoRuntimeInit()
{
    // The init function must be called only once, or else the Go runtime will crash!
    if (INIT_NONE == InterlockedCompareExchange(&s_GoRuntimeInitialized, INIT_DOING, INIT_NONE))
    {
        RT0_CPUARCH_WINDOWS_LIB();
        InterlockedExchange(&s_GoRuntimeInitialized, INIT_DONE);
    }
    else
    {
        // Busy waiting for fast thread sync
        while (INIT_DONE != InterlockedCompareExchange(&s_GoRuntimeInitialized, INIT_DOING, INIT_DOING))
        {
        }
    }
}

#else

void CallWindowsStaticGoRuntimeInit()
{
}

#endif // __MSC_VER
