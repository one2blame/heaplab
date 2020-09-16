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
* `top_chunk` - prints the location and size of the top chunk.

## Summary

To summarize the House of Force technique and this lecture we:

* Utilized a heap overflow vulnerability to overwrite the `top_chunk`'s `size`
field in the heap.
* We made the `size` field of the `top_chunk` large enough to convince `malloc`
that we could allocate a very large chunk.
* We calculated the distance between the `top_chunk` and the `target` variable.
* We requested a chunk size large enough to land the `top_chunk` right before
the `target` variable.
* We requested another chunk, overwriting the contents of the `target` variable
with our value.

Using the steps listed above, we proved we could use the House of Force
technique to implement an arbitrary write primitive.

### Gaining code execution

Finally, we proved that we could gain code execution using the arbitrary write
implemented with the House of Force technique. With our arbitrary write, we
target the `__malloc_hook` function pointer contained within `glibc`'s data
section.

* `__malloc_hook` - a writeable function pointer that can be overwritten by the
program to specify a function to be called each time `malloc()` is called.

To gain code execution we:

* Followed the same steps as above to implement an arbitrary write.
* Wrote `/bin/sh\0` to the heap to be used later as an argument to `system()`.
* Overwrote `__malloc_hook` with `system()` found in `libc`.
* Requested another chunk, thus executing `malloc()` which is now `system()`.
We provide the address of `/bin/sh\0` on the heap as the `size` argument, thus
passing the argument `/bin/sh\0` to the `system()` call.

Alternatively, we also used `pwntools` to search for the `/bin/sh` string in
`glibc` and used that address as an argument to `system()`.

## Final notes

The House of Force technique works against `glibc` versions `2.28` and below.
`glibc` version `2.29` introduced a `top_chunk` size check that compares the
`size` field of the `top_chunk` to a variable called `system_mem`, mitigating
the technique.

The House of Force technique requires knowledge of the distance between the
`top_chunk` and the target, unless your target resides on the same heap. The
House of Force technique also requires that we are able to make arbitrarily
large requests to `malloc()`.
