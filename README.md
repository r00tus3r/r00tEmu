# r00tEmu

An emulation tool to do dynamic binary analysis. Developed using [Unicorn Engine](https://github.com/unicorn-engine/unicorn) and [Pylibelf](https://github.com/crackinglandia/pylibelf).

### Features:
* Supports basic x64 ELF programs
* Trace instructions
* Dump memory mappings and register values
* Given an address and length, outputs a hexdump
* Print program and section header info

### ToDo:
* Trace library calls, syscalls and memory accesses
* Add ARM support and emulate ARM busybox

It is still a work in progress. When complete, it will be useful for emulating and analysing binaries of different architectures.
