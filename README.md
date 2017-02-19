# Wireshark dissector for the WireGuard tunnel protocol
Wireshark dissector (written in Lua) for dissecting the [WireGuard][1] tunneling
protocol.

Requirements:

 - Wireshark 2.0.2 or newer.
 - [luagcrypt][2] for decryption support.

## Installation
Locate the Wireshark configuration directory (either `~/.wireshark` or
`~/.config/wireshark`). Create the `plugins` subdirectory and add:

 - `wg.lua` (from this project)
 - `luagcrypt.so` (from the [luagcrypt][2] project).

To check whether it is installed correctly, run `tshark -G protocols | grep wg`.

Since WireGuard does not have a default port number, it is recommended to enable
the UDP protocol preference *Try heuristic sub-dissectors first* (via the menu
Edit → Preferences, Protocols → UDP).

TODO decryption is not implemented yet.

## Obtaining secrets through extract-keys
The `extract-keys` utility included with WireGuard can be used to extract keys
from kernel memory.  This requires the `CONFIG_DEVKMEM=y` option which is often
disabled on distribution kernels (like for Arch Linux and Debian).

If you have a suitable kernel and its kernel headers, follow either example in
the following sections.

### From tarball
At least with version 0.0.20170214 you need to add an additional include
directory:

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

 [1]: https://www.wireguard.io/
 [2]: https://github.com/Lekensteyn/luagcrypt
