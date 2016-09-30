#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include <list.h>
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
//#include "lib/stdbool.h"
void check_arg(struct intr_frame *f, int *args, int paremc);
static bool is_user(const void* vaddr);
static struct lock locker;
static struct fd_elem* find_file(int number);
static bool is_user(const void* vaddr){
	return vaddr < PHYS_BASE;
}


struct fd_elem{
	struct list_elem elem;
	struct file *file;
	int handle;
};

static void syscall_handler (struct intr_frame *);

/*
Implement enough code to read the system call number from the user stack and dispatch to a handler based on it.
*/

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&locker);
  list_init (&file_list);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int call = * (int *)f->esp;
  // Check for which call it is
  
  switch(call) {
    /* Halt the operating system. */
    case SYS_HALT:
      {
        halt();
        break;
      }
      
    /* Terminate this process. */
    case SYS_EXIT:                  
      {
        break;
      }
      
    /* Start another process. */
    case SYS_EXEC:                  
      {
        break;
      }
      
    /* Wait for a child process to die. */
    case SYS_WAIT:                  
      {
        break;
      }
      
    /* Create a file. */
    case SYS_CREATE:               
      {
		
        break;
      }
      
    /* Delete a file. */
    case SYS_REMOVE:               
      {
        break;
      }
      
    /* Open a file. */
    case SYS_OPEN:                  
      {
        break;
      }
      
    /* Obtain a file's size. */
    case SYS_FILESIZE:              
      {
        break;
      }
      
    /* Read from a file. */
    case SYS_READ:                  
      {
        break;
      }
      
    /* Write to a file. */
    case SYS_WRITE:                 
      {
        break;
      }
      
    /* Change position in a file. */
    case SYS_SEEK:                  
      {
        break;
      }
      
    /* Report current position in a file. */
    case SYS_TELL: 
      {
        break;
      }
      
    /* Close a file. */
    case SYS_CLOSE:
      {
        break;
      }
  }
  
  printf ("system call!\n");
  thread_exit ();
}
void check_arg(struct intr_frame *f, int *args, int paremc){
	int *ptr;
	ptr = f->esp;
	if(!is_user(ptr)){
		exit(-1);
	}
	if(*ptr <SYS_HALT){
		exit(-1);
	}
	for(int i =0; i < paremc ; i++){
		if(!is_user(ptr+i+1)){
			exit(-1);
		}
		args[i]=*ptr;
	}


}

/* Terminates Pintos by calling power_off() (declared in threads/init.h). This should be seldom used, because you lose some information about
possible deadlock situations, etc. */
void halt (void) {
  shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel. If the process's parent waits for it (see below), this is the status that will be returned. 
Conventionally, a status of 0 indicates success and nonzero values indicate errors. */
void exit (int status) {
  
  	thread_exit();
  
}

/* Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). 
Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return 
from the exec until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this. */
tid_t exec (const char *cmd_line) {

  

return -1;
}

/* 
If process pid is still alive, waits until it dies. Then, returns the status that pid passed to exit, or -1 if pid was terminated by the kernel 
(e.g. killed due to an exception). 
If pid does not refer to a child of the calling thread, or if wait has already been successfully called for the given pid, returns -1 immediately, without waiting.
You must ensure that Pintos does not terminate until the initial process exits. The supplied Pintos code tries to do this by calling 
process_wait() (in userprog/process.c) 
from main() (in threads/init.c). We suggest that you implement process_wait() according to the comment at the top of the function and then 
implement the wait system call in terms of process_wait().

All of a process's resources, including its struct thread, must be freed whether its parent ever waits for it or not, and regardless of whether the 
child exits before or after its parent.

Children are not inherited: if A has child B and B has child C, then wait(C) always returns immediately when called from A, even if B is dead.

Consider all the ways a wait can occur: nested waits (A waits for B, then B waits for C), multiple waits (A waits for B, then A waits for C), and so on.

Implementing this system call requires considerably more work than any of the rest.
*/
int wait (tid_t pid) {
  return 1;
}

/* Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. Creating a new file 
does not open it: opening the new file is a separate operation which would require a open system call. */
bool create (const char *file, unsigned initial_size) {
  return true;
}

/* Deletes the file called file. Returns true if successful, false otherwise. A file may be removed regardless of whether it is open or closed, 
and removing an open file does not close it. See Removing an Open File, for details. */
bool remove (const char *file) {
  return true;
}

/* Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output. 
The open system call will never return either of these file descriptors, which are valid as system call arguments only as explicitly described below.

Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.

When a single file is opened more than once, whether by a single process or different processes, each open returns a new file descriptor. 
	Different file descriptors for a single file are closed independently in separate calls to close and they do not share a file position. */
int open (const char *file) {
	char* file_to_open = copy_in_string(file);
	if(file_to_open == NULL){sys_exit(-1);}

	struct file_list *fd;
	fd = malloc (sizeof(*fd));
	
	int handle = -1;
	struct thread *current_thread = thread_current();
	if(fd != NULL){
		fd->file = filesys_open(file_to_open);
		if(fd->file !=NULL){
			current_thread->handle = current_thread->handle + 1;
			handle = current_thread->handle;
			fd->handle = current_thread->handle;
			list_push_front(&current_thread->file_lists, &fd->elem);
		}
		else{
			free(fd);
		}
	}		
	return handle;
}

/* Returns the size, in bytes, of the file open as fd. */
int filesize (int fd) {
  return 0;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), or -1 if the file could 
not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc(). */
int read (int fd, void *buffer, unsigned size) {
  return 0;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. The expected behavior is to 
write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all. */

/* Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(), 
at least as long as size is not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.) Otherwise, 
lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts. */
int write (int fd, const void *buffer, unsigned size) {
	struct file *f;
	int ret = -1;
	lock_acquire(&locker);
	if(fd == STDOUT_FILENO){
		putbuf(buffer, size);
	}else if(fd == STDIN_FILENO){
		lock_release(&locker);		
		return -1;
	}else if(!is_user(buffer)||is_user(buffer + size)){

		lock_release(&locker);
		return -1;
	}else{
		f = find_file(fd);
		if(!f){
			lock_release(&locker);
			return -1;
		}
		ret = file_write(f, buffer, size);

	}
	lock_release (&locker);
	return ret;


}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file. 
A later write extends the file, filling any unwritten gap with zeros. (However, in Pintos files have a fixed length until project 4 is complete, 
so writes past end of file will return an error.) These semantics are implemented in the file system and do not require any special effort in system call implementation. */
void seek (int fd, unsigned position) {

}

/* Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. */
unsigned tell (int fd) {
  return 0;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one. */
void close (int fd) {
	struct fd_elem  *file_to_close = find_file(fd);
	if(file_to_close == NULL){return;}
	file_close(file_to_close->file);
	list_remove(&file_to_close->elem);
	return;
}
/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one. */


struct fd_elem * find_file (int number){
	/* still to do:  get current file_list*/
	struct thread *current_thread = thread_current();
	struct list_elem *file_no;
	for(file_no = list_begin(current_thread->file_lists); file_no != list_end(current_thread->file_lists); file_no = list_next(file_no)){
		struct fd_elem *fl = list_entry(file_no, struct fd_elem, elem);
		if(fl->handle == number){
			return fl;
		}
	}
	sys_exit(-1);
	return(NULL); /*file not found*/
}
