#!/usr/bin/python2

from __future__ import print_function

import re
import sys
import subprocess
import struct


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("{}: missing core dump and/or binary".format(sys.argv[0]))
        sys.exit(1)
        # TODO: better usage

    exe      = sys.argv[0]
    coredump = sys.argv[1]
    binary   = sys.argv[2]

    print("{}: core dump - {} ; binary - {}".format(exe, coredump, binary))

    gadgets = {}

    gadget_file = "gadget_file"  # TODO: unique name?

    with open(gadget_file, 'w') as gf:
        subprocess.call(("ROPgadget --depth 4 --all --binary "
                         + binary).split(' '), stdout=gf)

    pattern_addr = re.compile("^0x[0-9a-f]+")
    with open(gadget_file, 'r') as gf:
        for line in gf:
            # Match the address from ROPgadget's output.
            addr = re.findall(pattern_addr, line)
            if len(addr) == 0:
                continue

            # Add that address as a gadget - True is a placeholder.
            gadgets[struct.pack("L", int(addr[0], 16))] = True

    print(gadgets)
