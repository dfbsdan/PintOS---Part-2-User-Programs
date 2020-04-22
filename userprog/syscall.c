#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);

void halt(void);
void exit(int status);
pid_t fork(const char *thread_name);
int exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int, fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	void *esp = f->rsp; /*get stack pointer from interrupt frame*/
	int sysnum;/*get syscall number from stack*/;
	get_argument(esp, &sysnum, 1)
	switch (sysnum){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit();
			break;
		case SYS_FORK:                   /* Clone current process. */

		case SYS_EXEC:                   /* Switch current process. */
		case SYS_WAIT:                   /* Wait for a child process to die. */
		case SYS_CREATE:                 /* Create a file. */
		case SYS_REMOVE:                 /* Delete a file. */
		case SYS_OPEN:                   /* Open a file. */
		case SYS_FILESIZE:               /* Obtain a file's size. */
		case SYS_READ:                   /* Read from a file. */
		case SYS_WRITE:                  /* Write to a file. */
		case SYS_SEEK:                   /* Change position in a file. */
		case SYS_TELL:                   /* Report current position in a file. */
		case SYS_CLOSE:
		default:
			thread_exit();
	}
}



void check_address(void *addr){
	if ()/*addr is not in user va*/
		thread_exit();
};


void get_argument(void *esp, int *arg, int count){
	check_address(esp);
	/*get*/
};




void halt(void){
	/* terminates pintos by calling power_off().*/
	power_off();
};


void exit(int status){
	struct thread *current = thread_current();
	/*terminates the current user program, returning status to the kernel.*/
	current->exit_status = status;
	thread_exit();
};


pid_t fork(const char *thread_name){
	/*create new process which is the clone of current process with the name THREAD_NAME.
	you don't need to clone the value of registers except %RBX, %RSP, %RBP, and %R12 - %R15 (callee saved registers)
	must return pid of child process, otherwise shouldn't be a valid pid.
	In child process, should return 0.
	child should have duplicated resources including file descriptor and virtual memory space.
	Parent should never return from forck until it knows child is successfully cloned.
	If child fails to duplicate the resourse, fork() call of parent should return TID_ERROR.
	*/
};

int exec(const char *cmd_line);
int wait(pid_t pid);


bool create(const char *file, unsigned initial_size){
	bool success;
	success = filesys_create(file, initial_size);
	return success;
};


bool remove(const char *file){
	bool success;
	success = filesys_remove(file);
	return success;
};


int open(const char *file);
int filesize(int, fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int
get_user (const uint8_t *uaddr) {
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
         : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}
