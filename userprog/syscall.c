#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

struct file_struct{
	int fd;
	struct file * file;
	struct list_elem file_elem;
};
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Obtains the file from the file descriptor assigned. */
struct file * getfile(int fd)
{
	struct list_elem * e;
	struct thread * t = thread_current ();
	for(e = list_begin(&(t->files));e!=list_end(&(t->files)); e = list_next(e))
	{
		struct file_struct * fp = list_entry(e,struct file_struct, file_elem);
		if(fp->fd==fd) return fp->file;
	}
	return NULL;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void sys_halt (){
	power_off();
} 

void sys_exit (int status){
	thread_exit(status);
}

int sys_exec (const char *file){
	printf("system call!\n");
}

int sys_wait (int child_pid){
	//return waiter(child_pid);
}

bool sys_create (const char *file, unsigned initial_size){
	if(is_user_vaddr(file)==0 || get_user(file) == -1 || file==NULL) sys_exit(-1);
	return filesys_create(file,initial_size);
}

bool sys_remove (const char *file){
	if(is_user_vaddr(file)==0 || get_user(file) == -1 || file==NULL) sys_exit(-1);
	return (filesys_remove(file)!=NULL);
}

int sys_open (const char *file){
	if(is_user_vaddr(file)==0 || get_user(file) == -1 || file==NULL) sys_exit(-1);
	struct file_struct * fp = malloc(sizeof(struct file_struct));
	fp->file = filesys_open(file);
	if(fp->file == NULL)
		return -1;

	list_push_back(&(thread_current ()->files),&(fp->file_elem));
	fp->fd = (thread_current() ->fd_last)++;
	return fp->fd;
}

int sys_filesize (int fd){
	return file_length(getfile(fd));
}

int sys_read (int fd, void *buffer, unsigned length){
	if(is_user_vaddr(buffer)==0 || get_user(buffer) == -1 || get_user(buffer+length) == -1)
		thread_exit(-1);

	if(fd==0){

	}

	struct file * file = getfile(fd);
	if(file==NULL){
		return 0;
	}

	return file_read(file,buffer,length);
}

int sys_write (int fd, const void *buffer, unsigned length){
	
	if(is_user_vaddr(buffer)==0 || get_user(buffer) == -1 || get_user(buffer+length) == -1)
		thread_exit(-1);

	if(fd==1){
			putbuf(buffer,length);
			return length;
	}

	struct file * file = getfile(fd);
	if(file==NULL){
		return 0;
	}

	return file_write(file,buffer,length);
}

void sys_seek (int fd, unsigned position){
	file_seek(getfile(fd),position);
}

unsigned sys_tell (int fd){
	return file_tell(getfile(fd));
}

void sys_close (int fd){
	struct list_elem * e;
	struct thread * t = thread_current ();
	for(e = list_begin(&(t->files));e!=list_end(&(t->files)); e = list_next(e))
	{
		struct file_struct * fp = list_entry(e,struct file_struct, file_elem);
		if(fp->fd==fd){
			list_remove(e);
			file_close(fp->file);
			return;
		}
	}
}

int verify(struct intr_frame *f){
	if(is_user_vaddr(f->esp) == 0 || get_user(f->esp) == -1)
		return 0;

	switch(*(int *)(f->esp)){ 

		//Allowing fallthrough because similar behaviour for multiple system calls.
		
		case 12:
		case 11:
		case 7:
		case 6:
		case 5:
		case 3:
		case 2:
		case 1:
			if(is_user_vaddr(f->esp+4)==0 || get_user(f->esp+4)==-1)
				return 0;

		case 10:
		case 4:
			if(is_user_vaddr(f->esp+4)==0 || get_user(f->esp+4)==-1)
				return 0;
			if(is_user_vaddr(f->esp+8)==0 || get_user(f->esp+8)==-1)
				return 0;

		case 8:
		case 9:
			if(is_user_vaddr(f->esp+4)==0 || get_user(f->esp+4)==-1)
				return 0;
			if(is_user_vaddr(f->esp+8)==0 || get_user(f->esp+8)==-1)
				return 0;
			if(is_user_vaddr(f->esp+12)==0 || get_user(f->esp+12)==-1)
				return 0;
		default:
			return 1;
	
	}
	return 1;
}

static void
syscall_handler (struct intr_frame *f) 
{
  int * p = f->esp;	
  if(verify(f)==0)
  	thread_exit(-1);

  switch(*(p)){
  	
  	case 0: sys_halt();
  			break;

  	case 1: sys_exit(*(p+1));
  			break;
 
  	case 2: 

  	case 3: f->eax = sys_wait(*(p+1));
  			break;

  	case 4: f->eax = sys_create(*(p+1),*(p+2));
  			break;

  	case 5: f->eax = sys_remove(*(p+1));
  			break;

  	case 6:	f->eax = sys_open(*(p+1));
  			break;

  	case 7: f->eax = sys_filesize(*(p+1));
  			break;

  	case 8: f->eax = sys_read(*(p+1),*(p+2),*(p+3));
  			break;

  	case 9: f->eax = sys_write(*(p+1),*(p+2),*(p+3));
  			break;
  	
  	case 10: sys_seek(*(p+1),*(p+2));
  			 break;

  	case 11: f->eax = sys_tell(*(p+1));
  			 break;

  	case 12: sys_close(*(p+1));
  			 break;
  }

}
