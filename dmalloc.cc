#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <climits>
#include <unordered_map> 
#include <string>
#include <iostream>
#include <math.h> 
#include <vector>
#include <algorithm>
using namespace std;

unsigned long long NUM_MALLOC = 0; // number of sucessful malloc calls
unsigned long long NUM_FREE = 0; // number of successful free calls
unsigned long long TOTAL_SIZE = 0; // all sizes of mallocs
unsigned long long NUM_FAIL = 0; // number of failed mallocs
unsigned long long FAIL_SIZE = 0; // size of failed mallocs
unsigned long long ACTIVE_SIZE = 0; // size of active mallocs
uintptr_t HEAP_MIN = ULONG_MAX; // smallest address allocated
uintptr_t HEAP_MAX = 0; // largest address allocated
unordered_map<string, size_t> HEAVY_HITTERS; // hash map for heavy hitters


struct header_t; // forward declaration (so header_t can be used in Node)

typedef struct Node { // linked list struct
    struct Node* next;
    header_t* head;
    int free;
} Node;

typedef struct header_t { // header struct
    char buffer[160]; // buffer for memcpy sanitizer warnings in tests 32 and 33
    size_t sz;
    int free; // block has been freed or not
    const char* file;
    long line;
    Node* listNode;
    char ow_prot[5]; // overwrite protection
} header_t;

typedef struct { // footer struct
    char ow_prot[300]; // overwrite protection
} footer_t;

Node* header_list = NULL;

void init_header(header_t* headPtr, size_t sz_in, const char* file_in, long line_in);
void init_footer(footer_t* footPtr);
int validFooter(footer_t* footPtr);
int validCanary(header_t* headPtr); 
void addNode(header_t* newHeader);
void notAllocated(void* ptr, const char* file, long line); 
void addHHnode(string fileLine, size_t bytes);

/// dmalloc_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then dmalloc_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    if (sizeof(header_t) + sizeof(footer_t) >= SIZE_MAX - sz) {
        NUM_FAIL++;
        FAIL_SIZE += sz;
        return NULL;
    } 

    void* ret = base_malloc(sz + sizeof(header_t) + sizeof(footer_t));

    uintptr_t temp = (uintptr_t) ret; // check alignment
    if (temp%8 != 0) {
        temp += (8 - (temp % 8));
    }

    header_t* headPtr = (header_t*) temp;
    if(headPtr==NULL) {
        NUM_FAIL++;
        FAIL_SIZE += sz; // can FAIL_SIZE wrap in loop?
        return NULL; // what to return if malloc fails?
    } else {

        NUM_MALLOC++;
        ACTIVE_SIZE += sz;
        TOTAL_SIZE += sz;
        
        init_header(headPtr, sz, file, line); // initialize header
        addNode(headPtr); // add to header linked list
        headPtr->listNode = header_list; // add node pointer to header

        headPtr++; // continue to point to first part of malloced memory

        if (HEAP_MIN == ULONG_MAX) { //update min and max
            HEAP_MIN = (uintptr_t)(headPtr);
        } else if ((uintptr_t)(headPtr) < HEAP_MIN) {
            HEAP_MIN = (uintptr_t)(headPtr);
        }
        if ((uintptr_t)(headPtr) + sz > HEAP_MAX) {
            HEAP_MAX = ((uintptr_t)(headPtr) + sz);
        }

        footer_t* footPtr = (footer_t*) ((uintptr_t)headPtr + sz);
        init_footer(footPtr); // initilaize footer

        // string concatenation of file and line
        string fileLine = file;
        fileLine += ":";
        fileLine += to_string(line);

        //srand(time(0)); // seed for random sampling
        //if (rand() % 10 != 0) { // random sampling
        //cout << fileLine << " " << sz << "\n"; 
            if (HEAVY_HITTERS.find(fileLine) == HEAVY_HITTERS.end()) { // fileLine not in map
                HEAVY_HITTERS[fileLine] = sz;
            } else { // file line already in map
                size_t curr = HEAVY_HITTERS[fileLine];
                HEAVY_HITTERS[fileLine] = curr + sz;
            }
        //}
        
        return (void*) headPtr;
    }
}



/// dmalloc_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to dmalloc_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void dmalloc_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    if (ptr) { //check if valid pointer

        if ((uintptr_t) ptr < HEAP_MIN || (uintptr_t) ptr > HEAP_MAX) {
            fprintf (stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n", file, line, ptr);
            abort();  
        }

        header_t* headPtr = (header_t*) ptr;
        headPtr--; // move to start of header

        uintptr_t temp = (uintptr_t) ptr; // check alignment
        if (temp%8 != 0) {
            fprintf (stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
            abort(); 
        }

        if(!validCanary(headPtr)) { //check canary fields 
            notAllocated(ptr, file, line);
        }

        if (headPtr->free != 0) { // check double free
            fprintf (stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n", file, line, ptr);
            abort();
        }

        if ((headPtr->listNode)->free == 1) { // check already freed
            fprintf (stderr, "MEMORY BUG: %s:%ld: free of pointer %p\n", file, line, ptr);
            abort();
        }

        footer_t* footPtr = (footer_t*) ((uintptr_t)(headPtr+1) + headPtr->sz);
        if(!validFooter(footPtr)) { // check wild write
            fprintf (stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n", file, line, ptr);
            abort();
        }

        ACTIVE_SIZE -= headPtr->sz;
        NUM_FREE++;
        headPtr->free = 1;
        (headPtr->listNode)->free = 1; // set node free value to 1
        base_free(headPtr);
    }
}


/// dmalloc_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {

    if (nmemb >= SIZE_MAX / sz) { // check for integer overflow
        NUM_FAIL++;
        FAIL_SIZE += sz * nmemb;
        return NULL;
    }

    void* ptr = dmalloc_malloc((nmemb * sz), file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz); 
    }
    return ptr;
}


/// dmalloc_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void dmalloc_get_statistics(dmalloc_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(dmalloc_statistics));
    stats->nactive = NUM_MALLOC - NUM_FREE;
    stats->active_size = ACTIVE_SIZE;
    stats->ntotal = NUM_MALLOC;
    stats->total_size = TOTAL_SIZE;
    stats->nfail = NUM_FAIL;
    stats->fail_size = FAIL_SIZE;
    stats->heap_min = HEAP_MIN;
    stats->heap_max = HEAP_MAX;
}


/// dmalloc_print_statistics()
///    Print the current memory statistics.

void dmalloc_print_statistics() {
    dmalloc_statistics stats;
    dmalloc_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// dmalloc_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void dmalloc_print_leak_report() {
    while(header_list != NULL) {
        if(header_list->free == 0) {
            printf("LEAK CHECK: %s:%ld: allocated object %p with size %zu\n", (header_list->head)->file, (header_list->head)->line, (header_list->head+1), (header_list->head)->sz); 
        }
        header_list = header_list->next;
    }
}


/// dmalloc_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void dmalloc_print_heavy_hitter_report() {
    unsigned long long hitter_size = TOTAL_SIZE / 6; // 20% of bytes allocated

    vector< pair<size_t,string>> vect; 
    for (auto x : HEAVY_HITTERS) {
        if(x.second >= hitter_size) {
            vect.push_back(make_pair(x.second,x.first)); 
        }
    }
    sort(vect.begin(), vect.end());
    for (int i = (int)vect.size() - 1; i > -1; i--) {
        double curr_percent = 100 * static_cast<float>(vect[i].first) / static_cast<float>(TOTAL_SIZE);
        cout << "HEAVY HITTER: " << vect[i].second << " " << vect[i].first << " bytes (~"; //<< curr_percent << "%)\n"; 
        printf("%0.1f", curr_percent);
        cout << "%)\n";
    }
}


// initialize header_t
void init_header(header_t* headPtr, size_t sz_in, const char* file_in, long line_in) {
    headPtr->sz = sz_in;
    headPtr->free = 0; // not freed
    headPtr->file = file_in;
    headPtr->line = line_in;
    for(int i = 0; i < 5; i++) {
        headPtr->ow_prot[i] = 'C';
    }
}

//  initialize footer
void init_footer(footer_t* footPtr) {
    for(int i = 0; i < 5; i++) {
        footPtr->ow_prot[i] = 'T';
    }
}

// check canary for out-of-bounds write (before freeing)
int validCanary(header_t* headPtr) {
    for(int i = 0; i < 5; i++) {
        if (headPtr->ow_prot[i] != 'C') {
            return 0;
        }
    }
    if (headPtr != headPtr->listNode->head) {
        return 0;
    }
    return 1; 
}

// check footer for out-of-bounds write (before freeing)
int validFooter(footer_t* footPtr) {
    for(int i = 0; i < 5; i++) {
        if (footPtr->ow_prot[i] != 'T') {
            return 0;
        }
    }
    return 1; 
}

// add node to list
void addNode(header_t* newHeader) {
    struct Node *tmpPtr = (struct Node *) malloc(sizeof(struct Node));
    tmpPtr->head = newHeader;
    tmpPtr->next = header_list;
    tmpPtr->free = 0;
    header_list = tmpPtr;
}

// print error message for unallocated pointer
void notAllocated(void* ptr, const char* file, long line) {
    fprintf (stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);

    while(header_list != NULL) {
        if((uintptr_t)(header_list->head+1) < (uintptr_t)ptr && ((uintptr_t)(header_list->head+1) + (uintptr_t)header_list->head->sz) > (uintptr_t)ptr) {
            fprintf (stderr, "  %s:%ld: %p is %zu bytes inside a %zu byte region allocated here\n", header_list->head->file, header_list->head->line, ptr, ((uintptr_t)ptr - (uintptr_t)(header_list->head+1)), header_list->head->sz);
            abort();
        }
        header_list = header_list->next;
    }
    abort();
}

