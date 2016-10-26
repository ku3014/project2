#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/block.h"
#include <stdbool.h>
#include <stdint.h>
#include <list.h>
#include <bitmap.h>

struct bitmap swap_table;
struct lock swap_lock;
struct block *swap_block;

void swap_init(void);
size_t swap_out(void * f);
void swap_in(size_t index, void * f);

#endif /* vm/swap.h */
