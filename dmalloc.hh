#ifndef M61_HH
#define M61_HH 1
#include <cassert>
#include <cstdlib>
#include <cinttypes>
#include <cstdio>
#include <new>


/// dmalloc_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
void* dmalloc_malloc(size_t sz, const char* file, long line);

/// dmalloc_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`.
void dmalloc_free(void* ptr, const char* file, long line);

/// dmalloc_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. The memory
///    should be initialized to zero.
void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line);


/// dmalloc_statistics
///    Structure tracking memory statistics.
struct dmalloc_statistics {
    unsigned long long nactive;         // # active allocations
    unsigned long long active_size;     // # bytes in active allocations
    unsigned long long ntotal;          // # total allocations
    unsigned long long total_size;      // # bytes in total allocations
    unsigned long long nfail;           // # failed allocation attempts
    unsigned long long fail_size;       // # bytes in failed alloc attempts
    uintptr_t heap_min;                 // smallest allocated addr
    uintptr_t heap_max;                 // largest allocated addr
};

/// dmalloc_get_statistics(stats)
///    Store the current memory statistics in `*stats`.
void dmalloc_get_statistics(dmalloc_statistics* stats);

/// dmalloc_print_statistics()
///    Print the current memory statistics.
void dmalloc_print_statistics();

/// dmalloc_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.
void dmalloc_print_leak_report();

/// dmalloc_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.
void dmalloc_print_heavy_hitter_report();

/// `dmalloc.cc` should use these functions rather than malloc() and free().
void* base_malloc(size_t sz);
void base_free(void* ptr);
void base_allocator_disable(bool is_disabled);


/// Override system versions with our versions.
#if !M61_DISABLE
#define malloc(sz)          dmalloc_malloc((sz), __FILE__, __LINE__)
#define free(ptr)           dmalloc_free((ptr), __FILE__, __LINE__)
#define calloc(nmemb, sz)   dmalloc_calloc((nmemb), (sz), __FILE__, __LINE__)
#endif


/// This magic class lets standard C++ containers use your debugging allocator,
/// instead of the system allocator.
template <typename T>
class dmalloc_allocator {
public:
    using value_type = T;
    dmalloc_allocator() noexcept = default;
    dmalloc_allocator(const dmalloc_allocator<T>&) noexcept = default;
    template <typename U> dmalloc_allocator(dmalloc_allocator<U>&) noexcept {}

    T* allocate(size_t n) {
        return reinterpret_cast<T*>(dmalloc_malloc(n * sizeof(T), "?", 0));
    }
    void deallocate(T* ptr, size_t) {
        dmalloc_free(ptr, "?", 0);
    }
};
template <typename T, typename U>
inline constexpr bool operator==(const dmalloc_allocator<T>&, const dmalloc_allocator<U>&) {
    return true;
}
template <typename T, typename U>
inline constexpr bool operator!=(const dmalloc_allocator<T>&, const dmalloc_allocator<U>&) {
    return false;
}

#endif
