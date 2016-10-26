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
#include "devices/block.h"
#include <bitmap.h>
#include "devices/disk.h"

void swap_init(){
	swap_block = block_get_role(BLOCK_SWAP);
	if(!swap_block){return;}
	swap_table = bitmap_create( block_size(swap_block) / (PGSIZE / BLOCK_SECTOR_SIZE));
	if(!swap_table){return;}
	bitmap_set_all(swap_table, 0);
	lock_init(&swap_lock);
}

/*when out of free frames, evict a page from its frame and put a copy of it
into swap disk, if necessary, to get a free frame*/
size_t swap_out(void *f){
	if(!swap_table){PANIC("swap_table NULL in swap_out");}
	if(!swap_block){PANIC("swap_block NULL in swap_out");}
	lock_acquire(&swap_lock);
	size_t index = bitmap_scan_and_flip(swap_table, 0, 1, 0);
	if(index == BITMAP_ERROR){PANIC("index error in swap_out");}
	for(size_t i = 0 ; i < PGSIZE/BLOCK_SECTOR_SIZE; i++){
		block_write(swap_block, index * (PGSIZE/BLOCK_SECTOR_SIZE) + i,
			    (uint8_t *) f + i *BLOCK_SECTOR_SIZE);
	}
	lock_release(&swap_lock);
	return index;
}

/*when page fault handler finds a page is not memory but in swap disk, allocate
a new frame and move it to memory */
void swap_in(size_t index, void * f){
	if(!swap_table){PANIC("swap_table NULL in swap_in");}
	if(!swap_block){PANIC("swap_block NULL in swap_in");}
	lock_acquire(&swap_lock);
	if(bitmap_test(swap_table, index) == 0){PANIC("index error in swap_in");}
	bitmap_flip(swap_table, index);
	for(size_t i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++){
		block_read(swap_block, index * (PGSIZE/BLOCK_SECTOR_SIZE) + i,
			    (uint8_t *) f + i *BLOCK_SECTOR_SIZE);
	
	}
	lock_release(&swap_lock);
	
}
/*NOTES: (1) only owning-process will ever page-in a page from swap
	 (2) owning-process must free used swap slots on exit
*/
