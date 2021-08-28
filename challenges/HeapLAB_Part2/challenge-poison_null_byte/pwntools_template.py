#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("poison_null_byte")
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

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

# Select the "free" option; send index.
def free(index):
    io.send("3")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ", timeout=1)

# Select the "read" option; read size bytes.
def read(index, size):
    io.send("4")
    io.sendafter("index: ", f"{index}")
    r = io.recv(size)
    io.recvuntil("> ")
    return r

io = start()
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Request 2 chunks.
chunk_A = malloc(0x88)
chunk_B = malloc(0x88)

# Edit "chunk_A".
edit(chunk_A, "Y"*8)

# Read from "chunk_A".
info(f"{read(chunk_A, 8)}")

# Free "chunk_A".
free(chunk_A)

# =============================================================================

io.interactive()
