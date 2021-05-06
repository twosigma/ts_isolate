`ts_isolate`
===

`ts_isolate` is a library to help you isolate (sandbox) builds and
tests, to improve build and test reliability.

In a large source code repository with many developers, it's
particularly important to "keep the build green" and ensure that all
merges to the main branch compile and pass tests. At scale, you'll
quickly run into flaky builds and tests, that is, builds and tests that
were passing when they were committed, but for some reason no longer
work right and frustrate an unrelated developer. However, at scale, it
becomes even more important to insist on keeping the build green instead
of allowing merges with failing builds and tests!

`ts_isolate` helps prevent flaky builds and tests from landing in the
first place by

* removing access to sources of non-determinism - specifically, by
  ensuring that developers cannot accidentally commit builds and tests
  that access network services, which may be unavailable in the future

* isolating builds and tests from the rest of the system - for instance,
  by allowing a test to bind to a port number without worrying if
  non-test code (or another test) is using it, or allowing a test to
  use `/dev/shm` without being impacted by code outside that test

* applying the same isolation to local builds and tests as to CI ones,
  reducing the "works on my machine" effect

We've been using this library in production at Two Sigma since late 2019
for all builds and tests in our multi-language monorepo (Java, Python,
C/C++, etc.), with specific exemptions for existing builds and tests that
do not work when isolated.

`ts_isolate` is specific to Linux and uses Linux kernel features
(primarily user namespaces) to isolate the process. It has no
dependencies beyond a C compiler and the usual libc and kernel
development headers.

Why would you want this?
===

Let's say you're writing some Python code that accesses your internal
Jira:

```python
import jira

JIRA_CLIENT = jira.JIRA("https://jira.example.com")

def list_overdue_tickets(user):
    for issue in JIRA_CLIENT.search_issues(...):
        ...
```

Simply importing this code causes a client to be created, which causes a
network request to your Jira instance. Even if you mock the
`JIRA_CLIENT` object when writing a test for `list_overdue_tickets`,
you've already made the network access just by loading this module.

Since your Jira instance is _usually_ running, you may not notice this -
but if Jira fails and you're trying to merge something to get it back
up, this may be the worst time for your "green" build to suddenly turn
"red".

`ts_isolate` prevents this by making sure your builds and tests -
including the builds and tests run locally by a developer before they
submit a change to CI - run under network isolation. Then, even when
your Jira instance is running, a developer will immediately see the code
above fail to compile or test.

Using the library
===

`ts_isolate` consists of a C library, `ts_isolate.so`, as well as a GNU
Make loadable plugin and a command-line utility. All of them accept a
space-separated list of isolation profiles, any of

`profiles` is a space-separated list of isolation profiles, any of

* `shm`: Create a private `/dev/shm` with a maximum size of 128 MB.
* `net`: Create a private network namespace (set of visible network
  devices), with only a loopback device configured as 192.0.2.2,
  isolating all network activity within the namespace and preventing
  external access.
* `gcc`: Deny access to `/usr/bin/gcc` and `/usr/bin/g++`, for
  environments where code should be using a separate compiler instead of
  an OS-packaged one.
* `python`: Deny access to system `python` and `python3` in `/usr/bin`, 
  For projects where code should be using a separate interpreter instead of an
  OS-packaged one.

Call `ts_isolate` at the beginning of your build or test runner, before
it runs any user-provided code. In our monorepo, the very first step in
building the monorepo from scratch is to compile `ts_isolate` and then
use it for all further builds, with each component of our monorepo able
to configure which profiles they want to use for builds. Our internal
test runner also runs `ts_isolate` before discovering or running any
tests.

The GNU Make plugin is an easy way of adding isolation to Make-based
builds. Add something like this to the top of your Makefile:

```make
ISOLATE := net
load path/to/ts_isolate_make.so
ifneq ($(ts_isolate ${ISOLATE}),ok)
   $(error ts_isolate failed)
endif
```

Then all commands run by Make will be subject to network isolation.

The `isolate` command takes a list of profiles as its first argument and
then runs a specified command. You can use it to isolate an existing
build tool or test runner, e.g.,

```
ts_isolate "net shm" python -m unittest
```

Finally, the C library is available for direct use from any language
with the ability to call C functions. It exposes a single function,
`int ts_isolate(const char *profiles)`, which returns 0 if isolation is
successful and -1 otherwise.

For instance, if you have a test wrapper in Python, you might want to
call

```python
lib = ctypes.CDLL("path/to/ts_isolate.so")
if lib.ts_isolate(" ".join(profiles)) != 0:
    raise Exception("ts_isolate failed")
```

before tests start. (Note that you'll want to run this before importing
any user-provided code, to make sure that imports don't contact the
network - this is more useful in a command that is going to run tests as
a subprocess than inside e.g. `setUpClass`.)

`ts_isolate` requires unprivileged user namespaces to be enabled. On
certain distributions, you may need to `echo 1 >
/proc/sys/kernel/unprivileged_userns_clone`. No other setup is required
(in particular, `ts_isolate` does not require subuid/subgid setup or
anything to be installed globally).

A note on security
===

`ts_isolate` is not a sandbox in the security sense. It is intended to
prevent _accidental_ external dependencies and to keep _well-behaved_
code separate from each other. It is extremely easy to write code that
"escapes" from isolation in a number of ways - among other things,
isolated code still has access to all your private data (SSH keys,
etc.).

If you're looking to build a sandbox for untrusted builds or tests, we
recommend taking a look at the
[bubblewrap](https://github.com/containers/bubblewrap) project, which is
actually intended to restrict what code can do.

One benefit of not being a sandbox is that isolated code still generally
appears to be in the user's environment, despite the namespaces. For
instance, the current hostname and username is preserved and all file
paths remain the same. This means that compiler error messages, log
messages from tests, etc., work the way you would expect instead of
referencing names inside a sandbox.

On the subject, we've chosen to write `ts_isolate` in C for two reasons.
Primarily, it happens at the very beginning of our build, and our
internal support for Rust and other safer languages is delivered through
our monorepo. Using Rust would require either a circular dependency in
our monorepo, a dependency on the OS-packaged version of Rust (which is
often old and doesn't have many dependencies available), or a separate
build process outside of our monorepo. `ts_isolate` also consists almost
entirely of uncommon Linux system calls inside a couple of `if`
statements, and so it would be largely unsafe code anyway and harder to
read. Since `ts_isolate` operates entirely on trusted inputs, C seems
like the right choice for now. We're
[huge](https://github.com/twosigma/fastfreeze)
[fans](https://github.com/twosigma/nsncd) of Rust and other safe
languages and we're looking forward to the day when writing code like
this in a language other than C makes sense.

Contributing
===

Contributions of new, generally useful profiles are welcome, as are
bindings or documentation for using it from various build or test
runners.

We've also gotten value from some very specific isolation profiles for
particular tests (e.g., hiding particular legacy paths and seeing if
builds and tests still work). The code isn't terribly long, so if you
have a site-specific isolation profile, maintaining a private fork may
be the right plan. We're happy to accept contributions to make it easier
to fit in your changes.
