#include "dmalloc.hh"
#include <cstdio>
#include <cassert>
#include <vector>
// Now C++ library functions call your allocator
// (but do not provide line number information).

int main() {
    // The `dmalloc_allocator<int>` argument tells the C++ standard library
    // to allocate `v`’s memory using `dmalloc_malloc/free`.
    std::vector<int, dmalloc_allocator<int>> v;
    for (int i = 0; i != 100; ++i) {
        v.push_back(i);
    }
    dmalloc_print_statistics();
}

//! alloc count: active          1   total    ??>=1??   fail          0
//! alloc size:  active  ??>=400??   total  ??>=400??   fail        ???
