#!/usr/bin/python2

from __future__ import print_function

import re
import sys
import subprocess
import struct

PTR_SIZE = 8
MIN_CHAIN_LENGTH = 3

def write_gadgets(gadget_file):
    with open(gadget_file, 'w') as gf:
        subprocess.call(("ROPgadget --depth 4 --all --binary "
                         + binary).split(' '), stdout=gf)


def populate_gadget_addresses(gadgets_dict, gadget_file):
    line_pattern = re.compile("(^0x[0-9a-f]+) : (.*)")
    with open(gadget_file, 'r') as gf:
        for line in gf:
            # Match the address and asm from ROPgadget's output.
            match = re.match(line_pattern, line)
            if match is None:
                # Not a gadget line (auxiliary ROPgadget output).
                continue

            gadgets_dict[struct.pack("L", int(match.group(1), 16))]\
                = match.group(2)

def search_coredump(gadget_dict, coredump):
    chains = []

    with open(coredump, "rb") as cd:
        curr_chain_len = 0
        curr_chain = []
        curr = cd.read(PTR_SIZE)

        while curr != "":
            try:
                asm = gadget_dict[curr]
                # We have a match
                curr_chain.append((curr, asm))
                curr_chain_len += 1
                print(curr_chain_len)
            except:
                # Not matching. Did we have a chain?
                if curr_chain_len != 0:
                    if curr_chain_len >= MIN_CHAIN_LENGTH:
                        # Potential payload.
                        chains.append(curr_chain)

                    curr_chain = []
                    curr_chain_len = 0

            curr = cd.read(PTR_SIZE)

        if curr_chain_len >= MIN_CHAIN_LENGTH:
            # Potential payload at the end.
            chains.append(curr_chain)

    return chains

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("{}: missing core dump and/or binary".format(sys.argv[0]))
        sys.exit(1)
        # TODO: better usage

    exe      = sys.argv[0]
    coredump = sys.argv[1]
    binary   = sys.argv[2]

    print("{}: core dump - {} ; binary - {}".format(exe, coredump, binary))

    gadget_file = "gadget_file"  # TODO: unique name?
    write_gadgets(gadget_file)

    gadgets = {}
    populate_gadget_addresses(gadgets, gadget_file)

    payloads = search_coredump(gadgets, coredump)

    print(gadgets)
    print(payloads)

