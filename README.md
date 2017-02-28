# Wireshark dissector for the WireGuard tunnel protocol
Wireshark dissector (written in Lua) for dissecting the [WireGuard][1] tunneling
protocol.

Requirements:

 - Wireshark 2.0.2 or newer (tested with Wireshark 2.3.x).
 - [luagcrypt][2] and Libgcrypt 1.7 for (optional) decryption support.

The plan is to eventually rewrite this prototype in a dissector that is included
with the main Wireshark sources.

## Installation
Locate the Wireshark configuration directory (either `~/.wireshark` or
`~/.config/wireshark`). Create the `plugins` subdirectory and add `wg.lua` (from
this project).

For decryption support, you must also install [luagcrypt][2]. Once you have
built that native library, install the resulting `luagcrypt.so` to
`/usr/lib/lua/5.2/luagcrypt.so`. Alternatively, set the environment variable
`LUA_CPATH=/path/to/luagcrypt/?.so` (including the `/?.so` suffix). You will
also need to obtain a keylog file (see the next sections) and configure it at
the WG protocol preferences.

To check whether it is installed correctly, run `tshark -G protocols | grep wg`.

Since WireGuard does not have a default port number, it is recommended to enable
the UDP protocol preference *Try heuristic sub-dissectors first* (via the menu
Edit → Preferences, Protocols → UDP).

## Obtaining handshake and traffic secrets through key-probe.sh and key-extract.py
Authenticated decryption of handshake fields and traffic data requires keys
which can be extracted from a host using `key-probe.sh` (included with this
project). This script sets tracepoints (using [*kprobes*][3]) which hooks on
WireGuard functions, allowing it to intercept keys and contextual information
(Sender and Receiver IDs).

It requires a kernel with `CONFIG_KPROBE_EVENT=y` (most distros satisfy this
requirement) with WireGuard loaded. Run `./key-probe.sh` as root to get started.
It will print the commands that were executed (and exit with non-zero exit code
if any step failed).

Next, obtain the trace output and extract keys from it. One approach, read once:

    sudo cat /sys/kernel/debug/tracing/trace > trace.txt
    ./key-extract.py < trace.txt > trace.keys

To continuously update the keylog file (useful for live captures):

    sudo cat /sys/kernel/debug/tracing/trace_pipe | ./key-extract.py > trace.keys

To stop logging more keys, disable the tracepoints with:

    sudo ./key-noprobe.sh

## Obtaining traffic secrets through extract-keys
The `extract-keys` utility included with WireGuard can be used to extract keys
from kernel memory.  This requires the `CONFIG_DEVKMEM=y` option which is often
disabled on distribution kernels (like for Arch Linux and Debian).

If you have a suitable kernel and its kernel headers, follow either example in
the following sections.

### From tarball
For versions before 0.0.20170214-1-g1c0ee32, you need to add an additional
include directory:

    cd contrib/examples/extract-keys
    KCFLAGS=-I$PWD/../../../src/compat/siphash/include make

### From system packages
On Arch Linux, the `wireguard-tools` package contains the `extract-keys` source
while the `wireguard-dkms` package contains the WireGuard kernel sources. It
needs to be patched though (for at least version 0.0.20170214):

    wgkdir=$(echo /usr/src/wireguard-*/)
    cp -a /usr/share/wireguard/examples/extract-keys/ .
    cd extract-keys
    sed "s;#include \".*/;#include \"${wgkdir}/;" config.c -i
    KCFLAGS=-I${wgkdir}/compat/siphash/include make

## License
Copyright (C) 2017 Peter Wu (peter@lekensteyn.nl)

This project is licensed under the GPLv2 (or any later version) license.
See [LICENSE.txt](LICENSE.txt) for more details.

 [1]: https://www.wireguard.io/
 [2]: https://github.com/Lekensteyn/luagcrypt
 [3]: https://www.kernel.org/doc/Documentation/trace/kprobetrace.txt
