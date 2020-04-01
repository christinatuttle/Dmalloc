# Dmalloc

A debugging memory allocator in C that will provide many of the features of Valgrind. 

Specifically, the debugging allocator...
1. Tracks memory usage,
2. Catches common programming errors (e.g., use after free, double free),
3. Detects writing off the end of dynamically allocated memory (e.g., writing 65 bytes into a 64-byte
piece of memory), and
4. Catches less common, somewhat devious, programming errors (memcpys and frees of allocated memory, etc)

The debugging allocator also includes heavy hitter reporting that tells a programmer where most of the dynamically-allocated memory is allocated.
