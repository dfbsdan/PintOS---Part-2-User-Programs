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

static void syscall_halt (void);
static void syscall_exit (int status);
static pid_t syscall_fork (const char *thread_name);
static int syscall_exec (const char *file);
static int syscall_wait (pid_t pid);
static bool syscall_create (const char *file, unsigned initial_size);
static bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned length);
static int syscall_write (int fd, const void *buffer, unsigned length);
static void syscall_seek (int fd, unsigned position);
static unsigned syscall_tell (int fd);
static void syscall_close (int fd);
static int syscall_dup2 (int oldfd, int newfd);

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
syscall_handler (struct intr_frame *f) {
	/////////////////////////////////////////////////////////////////////////////////////////////////////TESTING
	switch (f->R.rax) {
		case SYS_HALT:
			syscall_halt ();
			break;
		case SYS_EXIT:
			syscall_exit ((int)f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = (uint64_t)syscall_fork ((const char*)f->R.rdi);
			break;
		case SYS_EXEC:
			f->R.rax = (uint64_t)syscall_exec ((const char*)f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = (uint64_t)syscall_wait ((pid_t)f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = (uint64_t)syscall_create ((const char*)f->R.rdi, (unsigned)f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = (uint64_t)syscall_remove ((const char*)f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = (uint64_t)syscall_open ((const char*)f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = (uint64_t)syscall_filesize ((int)f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = (uint64_t)syscall_read ((int)f->R.rdi, (void*)f->R.rsi, (unsigned)f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = (uint64_t)syscall_write ((int)f->R.rdi, (const void*)f->R.rsi, (unsigned)f->R.rdx);
			break;
		case SYS_SEEK:
			syscall_seek ((int)f->R.rdi, (unsigned)f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = (uint64_t)syscall_tell ((int)f->R.rdi);
			break;
		case SYS_CLOSE:
			syscall_close ((int)f->R.rdi);
			break;
		/* Extra for Project 2 */
		case SYS_DUP2:
			f->R.rax = (uint64_t)syscall_dup2 ((int)f->R.rdi, (int)f->R.rsi);
			break;
		/* Project 3 and optionally project 4. */
		//case SYS_MMAP:			/* Map a file into memory. */
		//case SYS_MUNMAP:		/* Remove a memory mapping. */

		/* Project 4 only. */
		//case SYS_CHDIR:			/* Change the current directory. */
		//case SYS_MKDIR:			/* Create a directory. */
		//case SYS_READDIR:		/* Reads a directory entry. */
		//case SYS_ISDIR:			/* Tests if a fd represents a directory. */
		//case SYS_INUMBER:		/* Returns the inode number for a fd. */
		default:
			ASSERT (0);
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//printf ("system call!\n");
	//thread_exit ();
}

/* Halt the operating system. */
static void
syscall_halt (void) {
	ASSERT (0);
}

/* Terminate this process. */
static void
syscall_exit (int status) {
	ASSERT (0);
	//printf ("%s: exit(%d)\n", ...);
}

/* Clone current process. */
static pid_t
syscall_fork (const char *thread_name) {
	ASSERT (0);
}

/* Switch current process. */
static int
syscall_exec (const char *file) {
	ASSERT (0);
}

/* Wait for a child process to die. */
static int
syscall_wait (pid_t pid) {
	ASSERT (0);
}

/* Create a file. */
static bool
syscall_create (const char *file, unsigned initial_size) {
	ASSERT (0);
}

/* Delete a file. */
static bool
syscall_remove (const char *file) {
	ASSERT (0);
}

/* Open a file. */
static int
syscall_open (const char *file) {
	ASSERT (0);
}

/* Obtain a file's size. */
static int
syscall_filesize (int fd) {
	ASSERT (0);
}

/* Read from a file. */
static int
syscall_read (int fd, void *buffer, unsigned length) {
	ASSERT (0);
}

/* Write to a file. */
static int
syscall_write (int fd, const void *buffer, unsigned length) {
	ASSERT (0);
}

/* Change position in a file. */
static void
syscall_seek (int fd, unsigned position) {
	ASSERT (0);
}

/* Report current position in a file. */
static unsigned
syscall_tell (int fd) {
	ASSERT (0);
}

/* Close a file. */
static void
syscall_close (int fd) {
	ASSERT (0);
}

/* Duplicate the file descriptor */
static int
syscall_dup2 (int oldfd, int newfd) {
	ASSERT (0);
}
