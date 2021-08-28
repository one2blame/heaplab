#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_einherjar")
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
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send("3")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

io = start()

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Populate the username field.
username = "George"
io.sendafter("username: ", username)

# This program leaks its default heap start address.
io.recvuntil("heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil("> ")

# Request 2 chunks.
chunk_A = malloc(0x88)
chunk_B = malloc(0xf8)

# Free "chunk_A".
free(chunk_A)

# Edit "chunk_B".
edit(chunk_B, "X"*8)

# =============================================================================

io.interactive()
