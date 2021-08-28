#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_lore")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc is broken again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size.
# Returns chunk index.
def malloc(size):
    global index
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.recvuntil("> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send("2")
    io.sendafter("index: ",f"{index}")
    io.recvuntil("> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send("3")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil("heap @ ")
heap = int(io.recvline(), 16)

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Populate the "username" field.
username = "George"
io.sendafter("username: ", username)
io.recvuntil("> ")

# Request 2 "normal" chunks.
chunk_A = malloc(0x98)
chunk_B = malloc(0x88)

# Edit the first chunk.
edit(chunk_A, "Y"*8)

# Free the first chunk into the unsortedbin.
free(chunk_A)

# =============================================================================

io.interactive()
