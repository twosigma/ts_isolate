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

/* GNU Make plugin - call via something like
 * ISOLATE := net
 * load path/to/ts_isolate_make.so
 * ifneq ($(ts_isolate ${ISOLATE}),ok)
 *    $(error ts_isolate failed)
 * endif
 *
 * See also
 * https://www.gnu.org/software/make/manual/html_node/Loading-Objects.html#Loading-Objects
 */

#include <string.h>

#include <gnumake.h>

int ts_isolate(const char *profiles);

int plugin_is_GPL_compatible;

static char *
ts_isolate_helper(const char *name, unsigned int argc, char *argv[])
{
    if (ts_isolate(argv[0]) == 0) {
        char *ok = gmk_alloc(3);
        strcpy(ok, "ok");
        return ok;
    } else {
        return NULL;
    }
}

int
ts_isolate_make_gmk_setup(/*...*/)
{
    gmk_add_function("ts_isolate", ts_isolate_helper, 1, 1, 0);
    return 1;
}
