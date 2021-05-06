/*
 * Copyright (c) 2019-2021 Two Sigma Open Source, LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Isolate (sandbox) the current process via mechanisms such as user
 * namespaces or seccomp. This library contains the mechanisms; it's
 * designed to be called by builds and tests (e.g., through the Makefile
 * plugin or from your test runner), and the policy decisions of which
 * isolation mechanisms to use are up to the caller.
 *
 * To isolate the current process, call ts_isolate() with a
 * space-separated list of isolation profiles. On success, ts_isolate()
 * returns zero. On failure, ts_isolate() returns -1 and prints a
 * meaningful error message to stderr. (For the contexts where this
 * library is used, printing to stderr is reasonable.)
 *
 * If ts_isolate() fails, the process may be left in an unexpected state
 * (e.g., partial creation of a user namespace) and the calling code
 * should exit quickly instead of trying to do further work.
 *
 * Defined isolation profiles:
 *   shm:
 *     Creates a user + mount namespace and mounts a private /dev/shm
 *     with a maximum size of 128 MB.
 *   net:
 *     Denies all network access outside localhost.
 *   gcc:
 *     Denies access to /usr/bin/gcc and /usr/bin/g++, to ensure that
 *     the OS-packaged compiler is not accidentally used.
 *   ambient_admin:
 *     Retains capabilities in the newly-created namespace so that
 *     certain privileged operations like FUSE mounts work under
 *     isolation.
 */


#define _GNU_SOURCE
/* Older kernel headers are sensitive to include order - at the least,
 * sys/socket.h needs to come before linux/if.h and linux/route.h */
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <linux/audit.h>
#include <linux/bpf_common.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/route.h>
#include <linux/seccomp.h>
#include <err.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>

/* There's no header for these. From the manpage:
 *     These two system calls are the raw kernel  interface  for  getting  and
 *     setting  thread capabilities.  Not only are these system calls specific
 *     to Linux, but the kernel API is likely to change and use of these  sys‐
 *     tem  calls (in particular the format of the cap_user_*_t types) is sub‐
 *     ject to extension with each kernel revision, but old programs will keep
 *     working.
 * (The datatypes themselves are defined in <linux/capability.h> though.) */
extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);

/*** Helpers, mostly for error handling ***/

static int
vwrite_file(const char *filename, const char *format, va_list ap)
{
    FILE *stream = fopen(filename, "we");
    if (!stream) {
        warn("ts_isolate: fopen %s", filename);
        return -1;
    }

    if (vfprintf(stream, format, ap) < 0) {
        warn("ts_isolate: writing to %s", filename);
        fclose(stream);
        return -1;
    }

    if (fclose(stream) != 0) {
        warn("ts_isolate: close %s", filename);
        return -1;
    }
    return 0;
}

static int
write_file(const char *filename, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int ret = vwrite_file(filename, format, ap);
    va_end(ap);
    return ret;
}

static char *tempdir = NULL;

static int
overwrite_file(const char *filename, const char *format, ...)
{
    /* Write to a file we don't have write access to by bind-mounting a
     * new temporary file on top.
     *
     * The most obvious option is to use a normal temporary file routine
     * like mkstemp, but we don't have a good spot to clean it up. The
     * next-most-obvious option is to use a normal temporary file, bind
     * mount it, and then unlink it before returning control. This
     * _does_ work and the file doesn't get deleted from disk until the
     * mount is gone (it is treated much like a deleted open file), but
     * because it's deleted, you can't mount over it, i.e., you can't
     * nest ts_isolate inside ts_isolate (or a similar tool).
     *
     * So we create a temporary tmpfs, bind-mount a file inside it, and
     * unmount the tmpfs before returning control. This has the same
     * properties about keeping an open file in RAM until it's no longer
     * referenced, but it permits you to mount over it.
     *
     * (O_TMPFILE isn't an option here because the file is nameless and
     * therefore can't be bind-mounted at all.) */
    if (tempdir == NULL) {
        char template[] = "/tmp/ts_isolate.XXXXXX";
        if (mkdtemp(template) == NULL) {
            warn("ts_isolate: mkdtemp");
            return -1;
        }
        tempdir = strdup(template);
        if (tempdir == NULL) {
            warn("ts_isolate: strdup");
            rmdir(template);
            return -1;
        }
        if (mount("tmpfs", tempdir, "tmpfs", 0, NULL) != 0) {
            warn("ts_isolate: mount tmpfs");
            rmdir(tempdir);
            free(tempdir);
            tempdir = NULL;
            return -1;
        }
    }

    char *tempname;
    if (asprintf(&tempname, "%s/%s", tempdir, filename) < 0) {
        warn("ts_isolate: asprintf");
        /* From here on out, ts_isolate() will take care of making sure
         * to call cleanup_tempdir() */
        return -1;
    }
    for (char *s = strchr(tempname + strlen(tempdir) + 1, '/');
         s != NULL;
         s = strchr(s, '/')) {
        *s = '-';
    }

    va_list ap;
    va_start(ap, format);
    int ret = vwrite_file(tempname, format, ap);
    va_end(ap);
    if (ret != 0) {
        free(tempname);
        return -1;
    }

    if (mount(tempname, filename, NULL, MS_BIND, NULL) != 0) {
        warn("ts_isolate: bind mount over %s", filename);
        free(tempname);
        return -1;
    }

    free(tempname);
    return 0;
}

static void
cleanup_tempdir(void)
{
    if (tempdir == NULL)
        return;

    umount(tempdir);
    rmdir(tempdir);
    free(tempdir);
    /* Just in case we're called twice in the same process... */
    tempdir = NULL;
}

static int make_chown_a_noop(void) {
    /* This function handles a weird issue with the `patch` command (and
     * maybe other commands) in unprivileged user namespaces. When the
     * `patch` command modifies a file, it makes a new copy and then
     * renames it over the old file. It also tries to preserve the
     * ownership and permissions of the old file.
     *
     * In an unprivileged user namespace, only your primary UID and GID
     * get mapped. (You can map additional private UIDs/GIDs via e.g.
     * newuidmap, but not other existing UIDs/GIDs, and in any case,
     * ts_isolate does not assume newuidmap / subuids are configured.)
     * Everything else gets mapped to nobody:nogroup, which is not
     * actually a usable UID/GID inside the namespace (because it
     * represents multiple possible UIDs/GIDs outside the namespace).
     *
     * If the file you're patching was owned by a UID or GID that isn't
     * your primary UID/GID, `patch` will fail to preserve permissions
     * and throw an error.
     *
     * At Two Sigma, for historical reasons, users have a primary group
     * "twosigma" as well as a supplementary group named after their
     * username. User home directories are setgid to their personal
     * group, that is, new files in home directories are group-owned by
     * the personal group and not by the primary group. Therefore, the
     * above behavior causes `patch` to fail if run inside ts_isolate in
     * a Two Sigma home directory. (Note that `patch` doesn't even need
     * to do anything, since the real file on disk has the right
     * ownership - it's just that that ownership _appears_ to be
     * "nogroup" inside the namespace.)
     *
     * Since isolated builds and tests really should not be caring about
     * file ownership at all, we use seccomp to turn the syscalls for
     * changing file ownerships into no-ops that return zero. This
     * causes `patch` to believe the call succeeded instead of failing
     * the build.
     */
    struct sock_filter filter[] = {
        /* Ignore foreign-arch syscalls, since the syscall numbers are
         * different on different arches. This isn't a sandbox, so
         * permitting unknown syscalls is fine. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
#ifdef __x86_64__
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#else
#error "Add support for your architecture"
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* If it is chown etc., return 0 without doing anything */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chown, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchown, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lchown, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchownat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0),
        /* Otherwise, allow the syscall */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog fprog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0) != 0) {
        warn("ts_isolate: prctl(PR_SET_SECCOMP)");
        return -1;
    }

    return 0;
}

/*** Isolation profiles ***/

static int
ts_isolate_shm(void)
{
    if (mount("tmpfs", "/dev/shm", "tmpfs", 0, "size=128M") != 0) {
        warn("ts_isolate: shm: mount tmpfs on /dev/shm");
        return -1;
    }
    return 0;
}

static int
ts_isolate_net(void)
{
    /* ifconfig lo up */
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        warn("ts_isolate: socket");
        return -1;
    }
    struct ifreq ifreq = {
        .ifr_name = "lo",
    };
    if (ioctl(sock, SIOCGIFFLAGS, &ifreq) != 0) {
        warn("ts_isolate: SIOCGIFFLAGS lo");
        close(sock);
        return -1;
    }
    ifreq.ifr_flags |= IFF_UP;
    if (ioctl(sock, SIOCSIFFLAGS, &ifreq) != 0) {
        warn("ts_isolate: SIOCSIFFLAGS lo");
        close(sock);
        return -1;
    }

    /* ifconfig lo:0 192.0.2.2 up
     * Make sure we have a second IP address separate from 127.0.0.1
     * so that we can canonicalize our hostname to something other
     * than "localhost". This address is from the TEST-NET-1 range. */
    struct ifreq ifreq0 = {
        .ifr_name = "lo:0",
        .ifr_addr = {.sa_family = AF_INET},
    };
    ((struct sockaddr_in *)&ifreq0.ifr_addr)->sin_addr.s_addr = htonl(0xc0000202);
    if (ioctl(sock, SIOCSIFADDR, &ifreq0) != 0) {
        warn("ts_isolate: SIOCSIFADDR lo:0 192.0.2.2");
        close(sock);
        return -1;
    }

    /* route add 232.0.1.1 dev lo
     * Intentionally not permitting the entire multicast range,
     * because tests should only use this group (to avoid sending
     * real multicast traffic if run un-isolated). */
    struct rtentry rtentry = {
        .rt_dev = "lo",
        .rt_dst = {.sa_family = AF_INET},
        .rt_flags = RTF_UP | RTF_HOST,
    };
    ((struct sockaddr_in *)&rtentry.rt_dst)->sin_addr.s_addr = htonl(0xe8000101);
    if (ioctl(sock, SIOCADDRT, &rtentry) != 0) {
        warn("ts_isolate: SIOCADDRT lo 232.0.1.1");
        close(sock);
        return -1;
    }

    close(sock);

    /* echo 127.0.0.1 localhost > /etc/hosts
     * echo 192.0.2.2 $(hostname) >> /etc/hosts */
    struct utsname utsname;
    if (uname(&utsname) != 0) {
        warn("ts_isolate: uname");
        return -1;
    }
    if (overwrite_file(
                "/etc/hosts",
                "127.0.0.1 localhost\n192.0.2.2 %s\n",
                utsname.nodename)
            != 0) {
        return -1;
    }

    return 0;
}

static int
ts_isolate_gcc(void)
{
    const char *script = "#!/bin/sh\necho error: \"$0\" from OS not allowed >&2\nexit 1\n";
    const char *programs[] = {"/usr/bin/gcc", "/usr/bin/g++", NULL};
    for (int i = 0; programs[i]; i++) {
        if (overwrite_file(programs[i], "%s", script) != 0) {
            return -1;
        }
        if (chmod(programs[i], 0755) != 0) {
            warn("ts_isolate: chmod 755 %s", programs[i]);
            return -1;
        }
    }
    return 0;
}

static int
ts_isolate_python(void)
{
    const char *script = "#!/bin/sh\necho error: \"$0\" from OS not allowed >&2\nexit 1\n";
    const char *programs[] = {"/usr/bin/python", "/usr/bin/python3", NULL};
    for (int i = 0; programs[i]; i++) {
        if (overwrite_file(programs[i], "%s", script) != 0) {
            return -1;
        }
        if (chmod(programs[i], 0755) != 0) {
            warn("ts_isolate: chmod 755 %s", programs[i]);
            return -1;
        }
    }
    return 0;
}

static int
ts_isolate_ambient_admin(void)
{
    /* This is only intended for tests that need to run fusermount,
     * which is a setuid binary that work fine in an un-isolated
     * environment but breaks in a user namespace where we have no
     * mapping for root.
     *
     * Somewhat surprisingly, the namespaced fscaps stuff
     * https://brauner.github.io/2018/08/05/unprivileged-file-capabilities.html
     * still depends on the existence of a mapped UID 0, i.e., it
     * doesn't work in a pure capabilities environment. Since we
     * can't assume that we have multiple UIDs available via
     * /etc/subuid (or equivalent) and we want to map ourselves to
     * our original, non-root UID to make the environment look
     * normal, it seems there's no way of making an executable that
     * can regain capabilities once we drop them. So, we make it
     * ambient, which means everything can implicitly call mount().
     *
     * If you have some use case other than fusermount, don't use
     * this. Instead, make your test create a user namespace on its
     * own (via e.g. `unshare -Ur`), which will a) keep the test
     * working when run outside of isolation and b) not rely on
     * implementation details of ts_isolate.
     */

    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {0};
    if (capget(&header, data) != 0) {
        warn("ts_isolate: capget");
        return -1;
    }
    data[CAP_TO_INDEX(CAP_SYS_ADMIN)].inheritable |= CAP_TO_MASK(CAP_SYS_ADMIN);
    if (capset(&header, data) != 0) {
        warn("ts_isolate: capset cap_sys_admin+i");
        return -1;
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, 0, 0) != 0) {
        warn("ts_isolate: prctl(PR_CAP_AMBIENT raise CAP_SYS_ADMIN)");
        return -1;
    }
}

/*** Main function ***/

struct profile_spec {
    const char *name;
    int (*perform)(void);
    int namespaces;
    int enabled;
};

int
ts_isolate(const char *profiles)
{
    struct profile_spec specs[] = {
        {
            .name = "shm",
            .perform = ts_isolate_shm,
            .namespaces = CLONE_NEWNS,
        },
        {
            .name = "net",
            .perform = ts_isolate_net,
            /* We need a filesystem namespace for /etc/hosts */
            .namespaces = CLONE_NEWNS | CLONE_NEWNET,
        },
        {
            .name = "gcc",
            .perform = ts_isolate_gcc,
            .namespaces = CLONE_NEWNS,
        },
        {
            .name = "python",
            .perform = ts_isolate_python,
            .namespaces = CLONE_NEWNS
        },
        {
            .name = "ambient_admin",
            .perform = ts_isolate_ambient_admin,
            .namespaces = 0,
        }
    };
    const size_t num_specs = sizeof(specs) / sizeof(specs[0]);
    size_t i;

    while (*profiles) {
        size_t len = strcspn(profiles, " ");
        if (len == 0) {
            profiles++;
            continue;
        }

        for (i = 0; i < num_specs; i++) {
            if (strncmp(profiles, specs[i].name, len) == 0) {
                specs[i].enabled = 1;
                break;
            }
        }
        if (i == num_specs) {
            warnx("ts_isolate: Unknown profile '%.*s'", (int)len, profiles);
            return -1;
        }

        profiles += len;
    }

    uid_t orig_uid = geteuid();
    gid_t orig_gid = getegid();

    /* Create user namespace */
    int clone_args = 0;
    for (i = 0; i < num_specs; i++) {
        if (specs[i].enabled) {
            clone_args |= specs[i].namespaces;
        }
    }
    if (clone_args) {
        if (unshare(CLONE_NEWUSER | clone_args) != 0) {
            warn("ts_isolate: unshare");
            return -1;
        }

        if (write_file("/proc/self/setgroups", "deny") != 0) {
            return -1;
        }
        if (write_file("/proc/self/gid_map", "%1$d %1$d 1", orig_gid) != 0) {
            return -1;
        }
        if (write_file("/proc/self/uid_map", "%1$d %1$d 1", orig_uid) != 0) {
            return -1;
        }

        if (make_chown_a_noop() != 0) {
            return -1;
        }
    }

    /* Implement specific profiles */
    for (i = 0; i < num_specs; i++) {
        if (specs[i].enabled) {
            if (specs[i].perform() != 0) {
                cleanup_tempdir();
                return -1;
            }
        }
    }
    cleanup_tempdir();

    return 0;
}
