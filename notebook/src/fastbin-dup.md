# The Fastbin Dup

## Free

`malloc()` is really good at recycling used heap memory. This is achieved using
`free()` - a simple function that takes a pointer to a chunk to recycle said
chunk.

From `malloc()`'s perspective, however, the un-used chunk is linked into one of
several free lists. Our particular focus for this lecture is the `fastbin`.

## Fastbins

The `fastbins` are a small collection of singly-linked, non-circular free lists
that each hold free chunks of a specific size.

Here are some `pwndbg` commands for checking the bins:

* `bins` - prints the current status for all bins.
* `fastbins` - prints the current status for all `fastbins`.

It's shown in the lecture that `fastbins` are the exception to the `prev_inuse`
rule - our `prev_inuse` flag is still set even after the chunk has been
`free()`'d.

We can also notice that the chunk's user data has been overwritten with the
address of the previous chunk. This is the singly-linked list implementation
of the `fastbin` chunk list by `malloc()` and this pointer is called the
`forward pointer`.

In this lecture, `fastbins` similiarities are compared to `stack` data
structures. Each time a chunk is eligible to be in the `fastbin` is `free()`'d
and added to the `fastbin`, it is `push`ed onto the `stack`. When a chunk is
`malloc()`'d and an eligible `fastbin` exists, the chunk is `pop`ed from the
`stack`.

## Arenas

How can `pwndbg` keep track of what chunks are in the bins and what chunks are
currently being used? `malloc()` uses what are called `arenas` - structures
in which `malloc()` keeps track of all its non-inline metatdata, primarily the
heads of the free lists. A single `arena` can administrate multiple heaps, and
a new arena is created along with an initial heap each time a thread calls
`malloc()` for the first time. This is limited by the number of available
cores.

The `main()` thread gets a special arena called the `main arena` that resides
in the `glibc` `data` section. This is where `pwndbg` draws its information
from.

Some useful commands to inspect the `arenas`:

* `dq &main_arena <number of qwords>` - dumps the contents of the `main_arena`.

## fastbin_dup challenge

This challenge contains a double `free()` bug, a bug in which a program can
attempt to `free()` a chunk that is already free. The problem with a double
free is that a chunk can exhibit behavior where it can be allocated twice
because, if it can be free'd twice, it can be placed into the `fastbin` twice.
Effectively, it can be allocated for two different things at the same times,
two different locations of the program would be using the same pointer to a
chunk.

In order to implement an arbitrary write primitive, we:

* Allocate two chunks and free them in the same order.
* Execute a double free on the first chunk because it is not the head of the
`fastbin`.
* Now that a chunk is in the `fastbin` twice, we allocate the chunk and write
a pointer to our target in its user data, faking a forward pointer in the
`fastbin` to point to a fake chunk (our write target).
* We allocate chunks from the `fastbin` until we allocate the fake chunk that
contains our target and then we overwrite the value of the `target` variable.

## Misc

These are some miscellaneous but good commands encountered in this lecture:

* `ptype` - prints the type of a symbol, useful for understanding the items
within a `struct`.
