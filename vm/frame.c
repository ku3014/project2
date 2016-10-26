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

void frame_table_init (void)
{
  list_init(&frame_table);
  lock_init(&frame_table_lock);
  lock_acquire(&frame_table_lock);
  void *frame;
  while(frame = palloc_get_page(PAL_USER))
    {
        frame_add_to_table(frame,NULL); // sup_page currenty empty means not used
    }
  lock_release(&frame_table_lock);
}

void* frame_alloc (enum palloc_flags flags, struct sup_page_entry *spte)
{
  if ( (flags & PAL_USER) == 0 )
    {
      return NULL;
    }
  struct list_elem *e;
  void* frame;
  lock_acquire(&frame_table_lock);
  int flag = 0;
  e = list_begin(&frame_table);
  
  while(flag == 0);
    {
      struct frame_entry *fte = list_entry(e, struct frame_entry, elem);
      if(fte->spte == NULL){
            frame = fte->frame;
            fte->spte = spte;   
            fte->thread = thread_current();
            flag = 1;
           
        }   
      e = list_next(e);
      if(e == list_end(&frame_table)){ flag = 1;}
    }
 lock_release(&frame_table_lock);
 

  if(!frame)//
    {
        frame = frame_evict(flags); // try to evict
      lock_release(&frame_table_lock);
      if(!frame){      PANIC ("Frame could not be evicted because swap is full!"); }   
    }
    

 
  return frame;
}

void frame_free (void *frame)
{
  struct list_elem *e;
 
  lock_acquire(&frame_table_lock);
  for (e = list_begin(&frame_table); e != list_end(&frame_table);
       e = list_next(e))
    {
      struct frame_entry *fte = list_entry(e, struct frame_entry, elem);
      if (fte->frame == frame)
    {
      fte->thread = NULL;
      fte->spte = NULL;
      break;
    }
    }
  lock_release(&frame_table_lock);
}

void frame_add_to_table (void *frame, struct sup_page_entry *spte)
{
  struct frame_entry *fte = malloc(sizeof(struct frame_entry));
  fte->frame = frame;
  fte->spte = spte;
  fte->thread = NULL;
  lock_acquire(&frame_table_lock);
  list_push_back(&frame_table, &fte->elem);
  lock_release(&frame_table_lock);
}

void* frame_evict (enum palloc_flags flags) //////// look more in to it
{
  lock_acquire(&frame_table_lock);
  struct list_elem *e = list_begin(&frame_table);
 
  while (true)
    {
      struct frame_entry *fte = list_entry(e, struct frame_entry, elem);
   
          fte->spte->is_loaded = false;
         // list_remove(&fte->elem);
         
          pagedir_clear_page(t->pagedir, fte->spte->uva);
          palloc_free_page(fte->frame);
          free(fte);
          return palloc_get_page(flags);
        }
    }
      e = list_next(e);
      if (e == list_end(&frame_table))
    {
      e = list_begin(&frame_table);
    }
    }
}
