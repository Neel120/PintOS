#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"

static void syscall_handler (struct intr_frame *);
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
	printf("system call\n");
}

bool sys_remove (const char *file){
	printf("system call!\n");
}

int sys_open (const char *file){
	printf("system call!\n");
}

int sys_filesize (int fd){
	printf("system call!\n");
}

int sys_read (int fd, void *buffer, unsigned length){
	printf("system call!\n");
}

int sys_write (int fd, const void *buffer, unsigned length){
	
	if(is_user_vaddr(buffer)==0 || get_user(buffer) == -1 || get_user(buffer+length) == -1)
		thread_exit(-1);

	if(fd==1){
			putbuf(buffer,length);
			return length;
	}

}

void sys_seek (int fd, unsigned position){
	printf("system call\n");
}

unsigned sys_tell (int fd){
	printf("system call\n");
}

void sys_close (int fd){
	printf("system call\n");
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

  	case 4:

  	case 5:

  	case 6:

  	case 7:

  	case 8:

  	case 9: f->eax = sys_write(*(p+1),*(p+2),*(p+3));
  			break;
  	case 10:

  	case 11:

  	case 12:
  		break;
  }

}
