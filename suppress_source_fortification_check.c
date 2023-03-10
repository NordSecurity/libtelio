#include <string.h>

#if defined(__clang__)
void fortify_source()
{
    // UPDATE: armv7 and x86 architectures are affected.
    // Clang 9 (the one currently used for Android in NDK 21) has trouble with -D_FORTIFY_SOURCE.
    // None of the functions seem to be replaced with their checked function variants.
    // This is the only configuration I have found that triggers the replacement to a checked
    // function variant in clang.
    // https://developers.redhat.com/blog/2020/02/11/toward-_fortify_source-parity-between-clang-and-gcc
    char src[1] = "";
    char dst[1] = "";
    __builtin___strcpy_chk(dst, src, sizeof(dst));
}
#elif defined(__GNUC__)
char fortify_source()
{
    // volatile prevents the compiler from assuming the value of `length`
    // at compile time, hence forcing the compiler to replace `memcpy`
    // with `__memcpy_chk`.
    volatile int length = 0;
    char destination = 0;
    char source = 0;
    memcpy(&destination, &source, length);
    return destination;
}
#elif defined(_MSC_VER)
void fortify_source()
{
    // Empty function in order to satisfy the linker
}
#endif
