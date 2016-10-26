#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

void swap_init(){}


/*when out of free frames, evict a page from its frame and put a copy of it
into swap disk, if necessary, to get a free frame*/
size_t swap_out(void *frame){}

/*when page fault handler finds a page is not memory but in swap disk, allocate
a new frame and move it to memory */
void swap_in(size_t used_index, void * frame){}

/*method to keep track of whether a page has been swapped and in which part of swap disk a page
has been stored if so*/
void is_swap(){}

/*NOTES: (1) only owning-process will ever page-in a page from swap
	 (2) owning-process must free used swap slots on exit
*/
