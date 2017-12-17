#!/usr/bin/python2

from __future__ import print_function

import collections
import os
import os.path
import re
import resource
import struct
import subprocess
import sys
import tempfile

WORD_SIZE = 8
MIN_CHAIN_LENGTH = 5
tmp_file = None

"""Tuple to be associated with each gadget address.
    asm      : textual representation of instructions.
    source   : file the gadget comes from.
    pops     : number of pop instructions in gadget.
    pushes   : number of push instructions in gadget.
    calls    : number of call instructions in gadget.
    ints     : number of int instructions in gadget.
    iret     : number of iret instructions in gadget.
    d_before : Maximum number of data words (i.e. not special addresses)
               that *may* be present BEFORE this gadget. Comes from
               pushing to the stack (incl. calls). 1 is added to simplify
               search.
    d_after  : Like d_before but AFTER the gadget. Comes from popping from
               the stack.
"""
GadgetInfo = collections.namedtuple("GadgetInfo",
                                    "asm source pops pushes calls ints " +\
                                    "irets d_before d_after")

"""Populates gadgets_dict with all the gadgets found in the
   binaries in offsets, accounting for the load location.
"""
def populate_gadget_addresses(offsets, gadgets_dict):
    line_pattern = re.compile("(^0x[0-9a-f]+) : (.*)")

    for binary, offset in offsets.items():
        with open(tmp_file, 'w+') as gf:
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
                                 None, None, None, None)

"""Adds to gadgets_dict all functions found in the binaries in
   offsets, accounting for the load locations. Sets d_before to
   2 and other numerical fields to 0 in GadgetInfo.
"""
def populate_function_addresses(offsets, gadgets_dict):
    line_pattern = re.compile("(^[0-9a-f]+) (.) (.*)")

    for binary, offset in offsets.items():
        with open(tmp_file, 'w+') as ff:
            subprocess.call(["nm", binary], stdout=ff)

            ff.write("GENERATED FROM: " + binary)

            ff.seek(0)
            for line in ff:
                # Match the address, type, and name nm's output.
                match = re.match(line_pattern, line)
                if match is None:
                    # Some lines won't much but we don't need them.
                    continue

                if match.group(2) not in "WwTt":
                    # We only want local functions.
                    continue

                gadgets_dict[struct.pack("L", int(match.group(1), 16)\
                                              + struct.unpack("L", offset)[0])]\
                    = GadgetInfo("[function : {}]".format(match.group(3)),
                                 binary, 0, 0, 0, 0, 0, 2, 0)
                # ^2 is hardcoded - function calls will thrash a lot of the
                # payload.

"""Analyses the gadgets in gadget_dict. Gadgets are checked to see how
   much unspecific data may be contained before or after them on the
   stack. Certain instructions are also counted for debugging.
"""
def analyse_gadgets(gadget_dict):
    for gadget in gadget_dict.iterkeys():
        asm = gadget_dict[gadget].asm

        pops   = 0
        pushes = 0
        calls  = 0
        ints   = 0
        irets  = 0
        d_after  = 0
        d_before = 0

        d = 0

        # Count instructions - work out how much data we can have before/after.
        instr_pattern = re.compile("pop|push|call|int|iret")
        instructions_found = re.findall(instr_pattern, asm)
        for instruction in instructions_found:
            if "pop" in instruction:
                pops += 1
                d -= 1
            elif "iret" in instruction:
                irets += 1
                # Though it actually pops twice, we treat it as a
                # normal ret after the first pop.
                d -= 1
            elif "push" in instruction:
                pushes += 1
                d += 1
            elif "int" in instruction:
                ints += 1
                d += 2
            elif "syscall" in instruction:
                # Do nothing - syscall requires a manual push.
                pass
            else:  # call in instruction
                calls += 1
                d += 1

            # We might push further before the gadget or pop
            # further after it.
            if d < 0:
                if abs(d) > d_after:
                    d_after = abs(d)
            else:
                if d > d_before:
                    d_before = d

        gadget_dict[gadget] = gadget_dict[gadget]._replace(pops=pops,
                                                           pushes=pushes,
                                                           calls=calls,
                                                           ints=ints,
                                                           irets=irets,
                                                           d_before=d_before + 1,
                                                           d_after=d_after)


"""Searches the core dump for what look like payloads."""
def search_coredump(gadget_dict, coredump):
    chains = []

    with open(coredump, "rb") as cd:
        curr_chain_len = 0
        curr_chain = []
        curr_chain_start = 0
        curr = cd.read(WORD_SIZE)

        last_d_after = 0
        while curr != "":
            try:
                gadget_info = gadget_dict[curr]
                # We have a match

                last_d_after = gadget_info.d_after
                asm = gadget_info.asm
                source = gadget_info.source

                if curr_chain_len == 0:
                    curr_chain_start = cd.tell() - WORD_SIZE
                curr_chain.append((curr, source, asm))
                curr_chain_len += 1
            except:
                # Not matching.
                # 1. Did the last gadget potentially have garbage afterwards?
                if last_d_after != 0:
                    curr_chain.append((curr, "hand-picked?", "data"))
                    curr_chain_len += 1

                    for i in range(last_d_after - 1):
                        curr = cd.read(WORD_SIZE)
                        if curr is None:
                            break

                        curr_chain.append((curr, "hand-picked?", "data"))
                        curr_chain_len += 1

                    curr = cd.read(WORD_SIZE)

                    try:
                        gadget_info = gadget_dict[curr]
                        # We're good to keep moving and we'll match
                        # the gadget in the next iteration.
                        continue
                    except:
                        # No gadget after the garbage, we'll increase the
                        # chain length (benefit of the doubt) by ONE
                        # and maybe end it there, depending on (2).
                        curr_chain_len += 1
                        pass

                # 2. Read 3 ahead, is there a gadget there that has garbage
                #    before it?
                skipped = 1
                found = False
                for skipped in range(1, 4):
                    if curr is None:
                        break

                    if curr not in gadget_dict:
                        curr_chain.append((curr, "thrashed?", "data"))
                        curr_chain_len += 1
                        curr = cd.read(WORD_SIZE)
                        continue


                    # There's a gadget - does it have garbage before?
                    gadget_info = gadget_dict[curr]
                    if gadget_info.d_before >= skipped\
                       and gadget_info.d_before <= skipped + last_d_after:
                        found = True
                        break

                    # Coincidence - or the gadget address was the data.
                    curr_chain.append((curr, "thrashed?", "data"))
                    curr_chain_len += 1
                    curr = cd.read(WORD_SIZE)
                    continue


                if found:
                    # It'll be matched.
                    continue

                # Not found - remove all which has been skipped.
                for i in range(0, skipped):
                    curr_chain.pop()
                    curr_chain_len -= 1

                # Chain has ended.
                if curr_chain_len != 0:
                    if curr_chain_len >= MIN_CHAIN_LENGTH:
                        # Potential payload.
                        chains.append((curr_chain_start, curr_chain))
                    else:
                        # We want to reconsider what we skipped as
                        # garbage.
                        cd.seek(-WORD_SIZE * last_d_after, 1)
                        cd.seek(-WORD_SIZE * skipped, 1)

                    curr_chain = []
                    curr_chain_len = 0
                    last_d_after = 0


            curr = cd.read(WORD_SIZE)

        if curr_chain_len >= MIN_CHAIN_LENGTH:
            # Potential payload at the end.
            chains.append((curr_chain_start, curr_chain))

    return chains

"""Outputs binary names whose gadgets are included in the search
   and where in virtual memory they are loaded.
"""
def print_sources(offsets):
    print("Gadget sources")
    for shared_lib, offset in offsets.items():
        print("  {0:#018x} [{1}]".format(struct.unpack("L", offset)[0],
                                         shared_lib))

"""Outputs the payloads found by search_coredump."""
def print_payloads(payloads):
    print("Found {} potential payloads".format(len(payloads)))
    for i, payload in zip(range(1, len(payloads) + 1), payloads):
        print("  Payload #{} - length: {} - location: {}"\
              .format(i, len(payload[1]), hex(payload[0])))
        for gadget in payload[1]:
            print("    {0:#018x} [{1}]: {2}".format(
                struct.unpack("L", gadget[0])[0], gadget[1], gadget[2]))

"""Adds loaded shared libraries and the location at which they were loaded
   to offsets.
"""
def add_shared_lib_offsets(offsets, coredump):
    with open(tmp_file, 'w+') as slf:
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

"""Returns True when a payload from search_coredump looks real, and
   False otherwise. This is to weed out strange payloads (e.g. same
   gadget 10 times in a row.
"""
def check_payload(gadget_dict, payload):
    # 1. If we have 10 equal, adjacent gadgets, it's probably a bad match
    # as core dumps have a lot of instances of tons of duplicate garbage.
    dup = 0
    prev_addr = None
    for gadget in payload:
        addr = gadget[0]
        if addr == prev_addr:
            dup += 1
        else:
            dup = 0

        if dup >= 9 and addr in gadget_dict:
            return False

        prev_addr = addr

    return True

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: {} COREDUMP BINARY".format(sys.argv[0]))
        sys.exit(1)

    exe      = sys.argv[0]
    coredump = sys.argv[1]
    binary   = sys.argv[2]

    if not (os.path.isfile(binary) and os.access(binary, os.R_OK)):
        print("{}: cannot read binary '{}'".format(exe, binary))
        sys.exit(2)

    if not (os.path.isfile(coredump) and os.access(coredump, os.R_OK)):
        print("{}: cannot read core dump '{}'".format(exe, coredump))
        sys.exit(2)

    print("{}: core dump - {} ; binary - {}".format(exe, coredump, binary))

    tmp_file = tempfile.mkstemp()
    os.close(tmp_file[0])
    # Use the name
    tmp_file = tmp_file[1]

    offsets = {}
    offsets[binary] = struct.pack("L", 0)
    add_shared_lib_offsets(offsets, coredump)

    gadgets = {}
    populate_gadget_addresses(offsets, gadgets)
    analyse_gadgets(gadgets)
    populate_function_addresses(offsets, gadgets)

    payloads = search_coredump(gadgets, coredump)
    payloads[:] = [p for p in payloads if check_payload(gadgets, p[1])]

    print("")
    print_sources(offsets)
    print("")
    print_payloads(payloads)

    os.remove(tmp_file)

    print(str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) +\
          "KB (max rss)")
    print("# of gadgets: " + str(len(gadgets)))

    #print(gadgets)
    #for key in gadgets.keys():
    #    print("   :" + str(gadgets[key]))
    #print(payloads)

