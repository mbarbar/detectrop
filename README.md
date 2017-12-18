# detectrop

`detectrop` is a tool to find all what may be ROP payloads in core dumps.

## Dependencies
* 64-bit Linux (untested anywhere else)
* Python 2
* GDB
* `nm`
* ROPgadget

## Usage
`./detectrop.py COREDUMP BINARY`

where COREDUMP is the core dump to search, and BINARY is the
executable the core dump came from.

