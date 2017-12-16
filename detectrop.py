#!/usr/bin/python2

from __future__ import print_function

import collections
import re
import sys
import subprocess
import struct

import resource

PTR_SIZE = 8
MIN_CHAIN_LENGTH = 3

"""Tuple to be associated with each gadget address.
    asm      : textual representation of instructions.
    source   : file the gadget comes from.
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
                                    "asm source pops pushes calls " +\
                                    "d_before d_after")

def write_gadgets(gadget_file):
    with open(gadget_file, 'w') as gf:
        subprocess.call(("ROPgadget --depth 8 --all --binary "
                         + binary).split(' '), stdout=gf)


def populate_gadget_addresses(offsets, gadgets_dict, gadget_file):
    line_pattern = re.compile("(^0x[0-9a-f]+) : (.*)")
    for binary, offset in offsets.items():
        with open(gadget_file, 'rx+') as gf:
            subprocess.call(["ROPgadget", "--depth", "8", "--all",
                             "--offset", hex(struct.unpack("L", offset)[0]),
                             "--binary", binary],
                            stdout=gf)

            gf.write("GENERATED FROM: " + binary)

            gf.seek(0)
            for line in gf:
                # Match the address and asm from ROPgadget's output.
                match = re.match(line_pattern, line)
                if match is None:
                    # Not a gadget line (auxiliary ROPgadget output).
                    continue

                gadgets_dict[struct.pack("L", int(match.group(1), 16))]\
                    = GadgetInfo(match.group(2), binary, None, None, None,
                                 None, None)

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

        last_d_after = 0
        while curr != "":
            try:
                gadget_info = gadget_dict[curr]
                # We have a match

                last_d_after = gadget_info.d_after
                asm = gadget_info.asm
                source = gadget_info.source
                curr_chain.append((curr, source, asm))
                curr_chain_len += 1
            except:
                # Not matching.
                # 1. Did the last gadget potentially have garbage afterwards?
                if last_d_after != 0:
                    curr = cd.read(PTR_SIZE)
                    for i in range(last_d_after - 1):
                        curr = cd.read(PTR_SIZE)
                        if curr is None:
                            break

                        curr_chain.append((curr, "data"))
                        curr_chain_len += 1

                    curr = cd.read(PTR_SIZE)

                    try:
                        gadget_info = gadget_dict[curr]
                        # We're good to keep moving and we'll match
                        # the gadget in the next iteration.
                        continue
                    except:
                        # No gadget after the garbage, we'll increase the
                        # chain length (benefit of the doubt) by ONE
                        # and maybe end it there, depending on (2).
                        pass

                # 2. Read 3 ahead, is there a gadget there that has garbage
                #    before it?
                """
                skipped = 1
                found = False
                for skipped in range(1, 4):
                    curr = cd.read(PTR_SIZE)
                    if curr is None:
                        break

                    curr_chain.append((curr, "data"))
                    curr_chain_len += 1

                    if curr not in gadget_dict:
                        continue

                    # There's a gadget - does it have garbage before?
                    gadget_info = gadget_dict[curr]
                    if gadget_info.d_before >= skipped\
                       and gadget_info.d_before < skipped + last_d_after:
                        found = True
                        break

                    # Coincidence - or the gadget address was the data.
                    continue


                if found:
                    curr_chain_len += skipped
                    # It'll be matched.
                    continue

                # Not found - remove all which has been skipped.
                for i in range(1, skipped):
                    curr_chain.pop()
                    curr_chain_len -= 1
                """

                # Chain has ended.
                if curr_chain_len != 0:
                    if curr_chain_len >= MIN_CHAIN_LENGTH:
                        # Potential payload.
                        chains.append(curr_chain)

                    curr_chain = []
                    curr_chain_len = 0
                    last_d_after = 0

            curr = cd.read(PTR_SIZE)

        if curr_chain_len >= MIN_CHAIN_LENGTH:
            # Potential payload at the end.
            chains.append(curr_chain)

    return chains

def print_sources(offsets):
    print("Gadget sources")
    for shared_lib, offset in offsets.items():
        print("  {0:#018x} [{1}]".format(struct.unpack("L", offset)[0],
                                         shared_lib))

def print_payloads(payloads):
    print("Found {} potential payloads".format(len(payloads)))
    for i, payload in zip(range(1, len(payloads) + 1), payloads):
        print("Payload #{}".format(i))
        for gadget in payload:
            print("  {0:#018x} [{1}]: {2}".format(
                struct.unpack("L", gadget[0])[0], gadget[1], gadget[2]))

def add_shared_lib_offsets(offsets, coredump):
    shared_lib_file = "shared_lib_file"  # TODO: unique name?
    with open(shared_lib_file, 'r+') as slf:
        subprocess.call(["gdb", "-c", coredump, "-batch", "-ex", "info shared"],
                        stdout=slf)

        # First group: where lib is loaded, second group: lib path.
        slf.seek(0)
        for line in slf.readlines():
            if not line.startswith("0x"):
                # GDB rubbish.
                continue

            table_entry = line.split(" ")

            offsets[table_entry[-1].rstrip('\n')] =\
                struct.pack("L", int(table_entry[0], 16))

def check_payload(gadget_dict, payload):
    # 1. If we have 6 equal, adjacent gadgets, it's probably a bad match
    # as core dumps have a lot of instances of tons of duplicate garbage.
    dup = 0
    prev_addr = None
    for gadget in payload:
        addr = gadget[0]
        if addr == prev_addr:
            dup += 1
        else:
            dup = 0

        if dup >= 6 and addr in gadget_dict:
            return False

        prev_addr = addr

    return True

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

    offsets = {}
    offsets[binary] = struct.pack("L", 0)
    add_shared_lib_offsets(offsets, coredump)

    gadgets = {}
    populate_gadget_addresses(offsets, gadgets, gadget_file)
    analyse_gadgets(gadgets)

    payloads = search_coredump(gadgets, coredump)
    payloads[:] = [p for p in payloads if check_payload(gadgets, p)]

    print("")
    print_sources(offsets)
    print("")
    print_payloads(payloads)

    print(str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) +\
          "KB (max rss)")
    print("# of gadgets: " + str(len(gadgets)))

    #print(gadgets)
    #for key in gadgets.keys():
    #    print("   :" + str(gadgets[key]))
    #print(payloads)

