#include "userprog/syscall.h"
#include "devices/shutdown.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include <string.h>
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include <stdlib.h>
//#include "lib/stdbool.h"


/*
static void halt (void);
static void exit(int);
static tid_t exec (const char *cmd_line);
static int wait (tid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
*/

void check_arg(struct intr_frame *f, int *args, int paremc);
static bool is_user(const void* vaddr);
static struct lock locker;
static struct fd_elem* find_file(int number);
static void syscall_handler (struct intr_frame *);
char * string_to_page(const char * string);

void halt (void);
void exit (int status);
tid_t exec(const char *cmd_line);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

static bool is_user(const void* vaddr){
	if(vaddr == NULL) {return false;}
	return (vaddr < PHYS_BASE && pagedir_get_page(thread_current()->pagedir, vaddr) != NULL); 
}

struct fd_elem{
	struct list_elem elem;
	struct file *file;
	int handle;
};

/*
Implement enough code to read the system call number from the user stack and dispatch to a handler based on it.
*/

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&locker);

}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // int call = * (int *)f->esp;
  // Check for which call it is
  int call = * (int *)f->esp;
  int args[3]; // 3 maxargs
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
	  check_arg(f, &args[0], 1);
	  	exit(args[0]);
        break;
      }
      
    /* Start another process. */
    case SYS_EXEC:                  
      {
		check_arg(f, &args[0], 1);
		f->eax = exec((const char*) args[0]);
        break;
      }
      
    /* Wait for a child process to die. */
    case SYS_WAIT:                  
      {
	check_arg(f,&args[0], 1);
	f->eax = wait((tid_t) args[0]);
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
		check_arg(f,&args[0],1);
		f->eax = open((const char*) args[0]);
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
		check_arg(f,&args[0],3);
		f->eax = write(args[0],(const void*) args[1], (unsigned) args[2]);
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
  
}
void check_arg(struct intr_frame *f, int *args, int paremc){
//	int ptr;
//	ptr = * (int *) f->esp + 1;
	if(!is_user(f->esp)){
		exit(-1);
	}
//	if(*ptr <SYS_HALT){
//		exit(-1);
//	}
	for(int i =0; i < paremc ; i++){
	//	if(!is_user(*(int*)f->esp+i+1)){
	//		exit(-1);
	//	}
		args[i]=*((int*) f->esp+1+i);
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
	
	// Retrieve current process
	struct thread *cur = thread_current();
	cur->process_status->exit_status = status;
  	thread_exit();
}

/* Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). 
Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return 
from the exec until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this. */
tid_t exec (const char *cmd_line) {

 tid_t tid;
 tid=  process_execute(cmd_line);

return tid;
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
  return process_wait(pid);
}

/* Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. Creating a new file 
does not open it: opening the new file is a separate operation which would require a open system call. */
bool create (const char *file, unsigned initial_size) {
  return filesys_create(file, initial_size);
}

/* Deletes the file called file. Returns true if successful, false otherwise. A file may be removed regardless of whether it is open or closed, 
and removing an open file does not close it. See Removing an Open File, for details. */
bool remove (const char *file) {
  return filesys_remove(file);
}

/* Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output. 
The open system call will never return either of these file descriptors, which are valid as system call arguments only as explicitly described below.

Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.

When a single file is opened more than once, whether by a single process or different processes, each open returns a new file descriptor. 
	Different file descriptors for a single file are closed independently in separate calls to close and they do not share a file position. */
int open (const char *file) {

	char* file_to_open = string_to_page(file);
	if(file_to_open == NULL){exit(-1);}

	struct fd_elem *fd;
	fd = malloc (sizeof *fd);
	
	int handle = -1;
	struct thread *current_thread = thread_current();
	if(fd != NULL){
		lock_acquire(&locker);
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
		lock_release(&locker);
	}		
	palloc_free_page(file_to_open);
	return handle;
}

/* Returns the size, in bytes, of the file open as fd. */
int filesize (int fd) {
	struct fd_elem * f = find_file(fd);
	lock_acquire(&locker);
	int file_size = file_length(f->file);
	lock_release(&locker);
	return file_size;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), or -1 if the file could 
not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc(). */
int read (int fd, void *buffer, unsigned size) {
	struct fd_elem *f = NULL;
	int num_bytes_read = 0;
	uint8_t  *buffer_byte = buffer;
	
	if(fd != STDIN_FILENO){f = find_file(fd);if(f == NULL){return -1;}} /*if not standard lookup file */
	
	lock_acquire(&locker);
	
	while(size > 0){
		int bytes;
		if(fd == STDIN_FILENO){
			strlcat(buffer_byte, input_getc(), 1);
			bytes = 1;
		}
		else{
			bytes = file_read(f->file, buffer_byte, size);
		}
		if(bytes < 0){
			if(num_bytes_read == 0){num_bytes_read = -1;}
			break;
		}
		num_bytes_read = num_bytes_read + bytes;
		size = size - bytes;
	}
	lock_release(&locker);
	return num_bytes_read;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. The expected behavior is to 
write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all. */

/* Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(), 
at least as long as size is not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.) Otherwise, 
lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts. */
int write (int fd, const void *buffer, unsigned size) {
	uint8_t *buffer_byte = buffer;		
	struct file *f;
	int num_bytes_written = 0;
	if(fd != STDOUT_FILENO){
		f = find_file(fd);
	} 

	lock_acquire(&locker);
	while(size > 0){
		int bytes;
		if(fd == STDOUT_FILENO){
			putbuf(buffer_byte, size);
			bytes = size;
		}else if(fd == STDIN_FILENO){
			lock_release(&locker);		
			return -1;
		}else if(!is_user(buffer)||is_user(buffer + size)){
			lock_release(&locker);
			return -1;
		}else{
			
			if(!f){
				lock_release(&locker);
				return -1;
			}
			bytes = file_write(f, buffer_byte, size);
		}
		num_bytes_written = num_bytes_written + bytes;
		size = size - bytes;
	}
	lock_release (&locker);
	return num_bytes_written;
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file. 
A later write extends the file, filling any unwritten gap with zeros. (However, in Pintos files have a fixed length until project 4 is complete, 
so writes past end of file will return an error.) These semantics are implemented in the file system and do not require any special effort in system call implementation. */
void seek (int fd, unsigned position) {
	struct fd_elem *f = find_file(fd);
	if(f == NULL){thread_exit();}
	file_seek(f->file, position);
}

/* Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. */
unsigned tell (int fd) {
	struct fd_elem *f = find_file(fd);
	if(f == NULL){thread_exit();}
	return file_tell(f->file);
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one. */
void close (int fd) {
	struct fd_elem  *file_to_close = find_file(fd);
	if(file_to_close == NULL){return;}
	lock_acquire(&locker);
	file_close(file_to_close->file);
	list_remove(&file_to_close->elem);
	lock_release(&locker);
	return;
}
/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one. */


struct fd_elem * find_file (int number){
	/* still to do:  get current file_list*/
	struct thread *current_thread = thread_current();
	struct list_elem *file_no;
	for(file_no = list_begin(&current_thread->file_lists); file_no != list_end(&current_thread->file_lists); file_no = list_next(file_no)){
		struct fd_elem *fl = list_entry(file_no, struct fd_elem, elem);
		if(fl->handle == number){
			return fl;
		}
	}
	exit(-1);
	return(NULL); /*file not found*/
}

char * string_to_page(const char *string){
	char *page;
	
	page = palloc_get_page(0);
	if (page == NULL){thread_exit();}
	
	for(int i = 0; i < PGSIZE; i++){
		if(string >= (char *) PHYS_BASE){
			palloc_free_page(page);
			thread_exit();
		}
		if(page[i] == '\0') {return page;}
	}
	page[PGSIZE -1] = '\0';
	return page;
}

/* Reads a byte at user virtual address UADDR must be below PHYS_BASE. Returns the byte value if successful, -1 if a segfault occured. */
static int get_user(const uint8_t *uaddr){
	int result;
	asm ("mov1 $1f, %0; movzb1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
	return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHY_BASE.
   Returns true if successful, false if a seqfault occurred. */
static bool put_user(uint8_t *udst, uint8_t byte) {
	int error_code;
	asm ("mov1 $1f, %0; movb %b2, %1: 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}
