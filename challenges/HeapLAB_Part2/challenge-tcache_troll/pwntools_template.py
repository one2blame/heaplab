#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("tcache_troll")
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

# Select the "malloc" option; send size & data.
# Returns chunk index.
def malloc(size, data):
    global index
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

# Select the "read" option.
# Returns 8 bytes.
def read(index):
    io.send("3")
    io.sendafter("index: ", f"{index}")
    r = io.recv(8)
    io.recvuntil("> ")
    return r

io = start()
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Request a 0x410-sized chunk and fill it with data.
chunk_A = malloc(0x408, "A"*0x408)

# Read the 1st quadword of chunk A's user data.
log.info(read(chunk_A))

# Free chunk A.
free(chunk_A)

# =============================================================================

io.interactive()
