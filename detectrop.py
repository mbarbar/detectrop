#!/usr/bin/python2

from __future__ import print_function

import collections
import re
import sys
import subprocess
import struct

PTR_SIZE = 8
MIN_CHAIN_LENGTH = 3

"""Tuple to be associated with each gadget address.
    asm      : textual representation of instructions.
    pops     : number of pop instructions in gadget.
    pushes   : number of push instructions in gadget.
    calls    : number of call instructions in gadget.
    d_before : Maximum number of data words (i.e. not special addresses)
               that *may* be present BEFORE this gadget. Comes from
               pushing to the stack (incl. calls).
    d_after  : Like d_before but AFTER the gadget. Comes from popping from
               the stack.
"""
GadgetInfo = collections.namedtuple("GadgetInfo",
                                    "asm pops pushes calls d_before d_after")

def write_gadgets(gadget_file):
    with open(gadget_file, 'w') as gf:
        subprocess.call(("ROPgadget --depth 8 --all --binary "
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
                = GadgetInfo(match.group(2), None, None, None, None, None)

def count_instructions(instruction, asm):
    substr = " {} ".format(instruction)
    return asm.count(substr)

def analyse_gadgets(gadget_dict):
    for gadget in gadget_dict.iterkeys():
        asm = gadget_dict[gadget].asm

        pops   = 0
        pushes = 0
        calls  = 0
        d_after = 0
        d_before = 0
        d = 0

        # Count instructions - work out how much data we can have before/after.
        instr_pattern = re.compile("pop|push|call")
        instructions_found = re.findall(instr_pattern, asm)
        for instruction in instructions_found:
            # TODO: see if it's worth handling variants - probably not.
            if "pop" in instruction:
                pops += 1
                d -= 1
            elif "push" in instruction:
                pushes += 1
                d += 1
            else:  # call in instruction
                calls += 1
                d += 1

            # We might push further before the gadget or pop
            # further after it.
            if d < 0:
                if abs(d) > d_before:
                    d_before = abs(d)
            else:
                if d > d_after:
                    d_after = d

        gadget_dict[gadget] = gadget_dict[gadget]._replace(pops=pops,
                                                           pushes=pushes,
                                                           calls=calls,
                                                           d_before=d_before,
                                                           d_after=d_after)


def search_coredump(gadget_dict, coredump):
    chains = []

    with open(coredump, "rb") as cd:
        curr_chain_len = 0
        curr_chain = []
        curr = cd.read(PTR_SIZE)

        while curr != "":
            try:
                asm = gadget_dict[curr].asm
                # We have a match
                curr_chain.append((curr, asm))
                curr_chain_len += 1
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

def print_payloads(payloads):
    print("Found {} potential payloads".format(len(payloads)))
    for i, payload in zip(range(1, len(payloads) + 1), payloads):
        print("Payload #{}".format(i))
        for gadget in payload:
            print("  {0:#08x} : {1}".format(struct.unpack("L", gadget[0])[0],
                                            gadget[1]))

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
    analyse_gadgets(gadgets)

    payloads = search_coredump(gadgets, coredump)

    print_payloads(payloads)

    #print(gadgets)
    #for key in gadgets.keys():
    #    print("   :" + str(gadgets[key]))
    #print(payloads)

