# The House of Force

## Chunks

The lecture provides a demonstration of how the process allocates heap memory
using the `malloc()` function with the `demo` application. Some things to note:

- The minimum chunk size returned by malloc is `0x20` or **32** bytes.
- The first `QWORD` of a chunk on the heap is used to contain the size field,
the total size of the chunk including the heap metadata.
- Just like the stack stores its metadata on the stack, the heap stores its
metadata on the heap.
- The `prev_inuse` flag is used to signify that the previous chunk is currently
in use. This flag is the first bit of the size field.
- The `top_chunk` is located at the highest address in the heap. The top chunk
is shrunk each time memory is requested by the process and grows when the space
represented by the top chunk is exhausted.
- The `top_chunk` has a size field, providing the heap allocator with a measure
of how much space is available in the `top_chunk`.
- In many versions of `glibc`, the `top_chunk` size field is not subject to
integrity checks.

## Pwndbg

These are some helpful `pwndbg` commands that were covered in this lecture:

* `dq <symbol>` - dump quadword; dumps the contents of the provided symbol
* `pwndbg <segment>` - provides help output and a listing of commands for a
particular segment in memory.
* `xinfo <symbol>` - provides extended information for an address in memory
* `vis` - dumps the contents of the heap
