/*
 * getrandom(2) shim for mips (o32) Linux.
 *
 * glibc 2.24 is the last release that supports the 32-bit big-endian mips
 * port, and getrandom(2) only appeared in glibc 2.25. Both `std` (via
 * `sys::random::linux::hashmap_random_keys`) and the `getrandom` crate call
 * the libc symbol unconditionally, so linking a mips binary fails with
 * "undefined reference to `getrandom'".
 *
 * The kernel side has existed since Linux 3.17, so the fix is to provide the
 * missing wrapper: issue the syscall directly. This is compiled only for
 * mips*-linux-gnu targets (see build.rs); every other target uses the real
 * libc function.
 */

#include <errno.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_getrandom
#define SYS_getrandom __NR_getrandom
#endif

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
    return (ssize_t)syscall((long)SYS_getrandom, buf, buflen, flags);
}
