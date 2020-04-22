#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/vaddr.h"
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
static int syscall_fork (const char *thread_name);
static int syscall_exec (const char *file);
static int syscall_wait (int pid);
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
////////////////////////////////////////////////////////////////////////////////////////////////////////TESTING
static void check_address(void *addr);
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
			f->R.rax = (uint64_t)syscall_wait ((int)f->R.rdi);
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
			ASSERT (0); //Unknown syscall (could not be implemented yet)
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//printf ("system call!\n");
	//thread_exit ();
}

/* Terminates Pintos by calling power_off(). This should be seldom used,
 * because you lose some information about possible deadlock situations,
 * etc. */
static void
syscall_halt (void) {
	power_off ();
}

/* Terminates the current user program, returning status to the kernel.
 * If the process's parent waits for it (see wait()), this is the status
 * that will be returned. Conventionally, a status of 0 indicates success
 * and nonzero values indicate errors. */
static void
syscall_exit (int status) {
	/////////////////////////////////////////////////////////////////////////////////////////////////////TESTING
	thread_current ()->exit_status = status;
	thread_exit ();
	/* Return exit status to waiting parent. */

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
}

/* Create new process which is the clone of current process with the name
 * THREAD_NAME. You don't need to clone the value of the registers except
 * %RBX, %RSP, %RBP, and %R12 - %R15, which are callee-saved registers.
 * Must return pid of the child process, otherwise shouldn't be a valid
 * pid. In child process, the return value should be 0. The child should
 * have DUPLICATED resources including file descriptor and virtual memory
 * space. Parent process should never return from the fork until it knows
 * whether the child process successfully cloned. That is, if the child
 * process fail to duplicate the resource, the fork () call of parent
 * should return the TID_ERROR.
 * The template utilizes the pml4_for_each() in threads/mmu.c to copy
 * entire user memory space, including corresponding pagetable structures,
 * but you need to fill missing parts of passed pte_for_each_func (See
 * virtual address). */
static int
syscall_fork (const char *thread_name UNUSED) {
	ASSERT (0);
}

/* Change current process to the executable whose name is given in
 * cmd_line, passing any given arguments. This never returns if
 * successful. Otherwise the process terminates with exit state -1, if the
 * program cannot load or run for any reason. This function does not
 * change the name of the thread that called exec. Please note that file
 * descriptors remain open across an exec call. */
static int
syscall_exec (const char *file UNUSED) {
	ASSERT (0);
}

/* Waits for a child process pid and retrieves the child's exit status. If
 * pid is still alive, waits until it terminates. Then, returns the status
 * that pid passed to exit. If pid did not call exit(), but was terminated
 * by the kernel (e.g. killed due to an exception), wait(pid) must return
 * -1. It is perfectly legal for a parent process to wait for child
 * processes that have already terminated by the time the parent calls
 * wait, but the kernel must still allow the parent to retrieve its child’s
 * exit status, or learn that the child was terminated by the kernel.
 * wait must fail and return -1 immediately if any of the following
 * conditions is true:
 * -pid does not refer to a direct child of the calling process. pid is a
 * direct child of the calling process if and only if the calling process
 * received pid as a return value from a successful call to exec. Note
 * that children are not inherited: if A spawns child B and B spawns child
 * process C, then A cannot wait for C, even if B is dead. A call to
 * wait(C) by process A must fail. Similarly, orphaned processes are not
 * assigned to a new parent if their parent process exits before they do.
 * The process that calls wait has already called wait on pid. That is, a
 * process may wait for any given child at most once.
 * Processes may spawn any number of children, wait for them in any order,
 * and may even exit without having waited for some or all of their
 * children. Your design should consider all the ways in which waits can
 * occur. All of a process's resources, including its struct thread, must
 * be freed whether its parent ever waits for it or not, and regardless of
 * whether the child exits before or after its parent.
 * You must ensure that Pintos does not terminate until the initial
 * process exits. The supplied Pintos code tries to do this by calling
 * process_wait() (in userprog/process.c) from main() (in threads/init.c).
 * We suggest that you implement process_wait() according to the comment
 * at the top of the function and then implement the wait system call in
 * terms of process_wait().
 * Implementing this system call requires considerably more work than any
 * of the rest. */
static int
syscall_wait (int pid UNUSED) {
	ASSERT (0);
}

/* Creates a new file called file initially initial_size bytes in size.
* Returns true if successful, false otherwise. Creating a new file does
* not open it: opening the new file is a separate operation which would
* require a open system call. */
static bool
syscall_create (const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

/* Deletes the file called file. Returns true if successful, false
 * otherwise. A file may be removed regardless of whether it is open or
 * closed, and removing an open file does not close it. See Removing an
 * Open File in FAQ for details. */
static bool
syscall_remove (const char *file) {
	return filesys_remove(file);
}

/* Opens the file called file. Returns a nonnegative integer handle called
 * a "file descriptor" (fd), or -1 if the file could not be opened. File
 * descriptors numbered 0 and 1 are reserved for the console: fd 0
 * (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard
 * output. The open system call will never return either of these file
 * descriptors, which are valid as system call arguments only as
 * explicitly described below. Each process has an independent set of file
 * descriptors. File descriptors are inherited by child processes. When a
 * single file is opened more than once, whether by a single process or
 * different processes, each open returns a new file descriptor. Different
 * file descriptors for a single file are closed independently in separate
 * calls to close and they do not share a file position. You should follow
 * the linux scheme, which returns integer starting from zero, to do the
 * extra. */
static int
syscall_open (const char *file UNUSED) {
	ASSERT (0);
}

/* Returns the size, in bytes, of the file open as fd. */
static int
syscall_filesize (int fd UNUSED) {
	ASSERT (0);
}

/* Reads size bytes from the file open as fd into buffer. Returns the
 * number of bytes actually read (0 at end of file), or -1 if the file
 * could not be read (due to a condition other than end of file). fd 0
 * reads from the keyboard using input_getc(). */
static int
syscall_read (int fd UNUSED, void *buffer UNUSED, unsigned length UNUSED) {
	ASSERT (0);
}

/* Writes size bytes from buffer to the open file fd. Returns the number
 * of bytes actually written, which may be less than size if some bytes
* could not be written. Writing past end-of-file would normally extend the
* file, but file growth is not implemented by the basic file system. The
* expected behavior is to write as many bytes as possible up to end-of-
* file and return the actual number written, or 0 if no bytes could be
* written at all. fd 1 writes to the console. Your code to write to the
* console should write all of buffer in one call to putbuf(), at least as
* long as size is not bigger than a few hundred bytes (It is reasonable to
* break up larger buffers). Otherwise, lines of text output by different
* processes may end up interleaved on the console, confusing both human
* readers and our grading scripts. */
static int
syscall_write (int fd UNUSED, const void *buffer UNUSED, unsigned length UNUSED) {
	ASSERT (0);
}

/* Changes the next byte to be read or written in open file fd to
 * position, expressed in bytes from the beginning of the file (Thus, a
 * position of 0 is the file's start). A seek past the current end of a
 * file is not an error. A later read obtains 0 bytes, indicating end of
 * file. A later write extends the file, filling any unwritten gap with
 * zeros. (However, in Pintos files have a fixed length until project 4 is
 * complete, so writes past end of file will return an error.) These
 * semantics are implemented in the file system and do not require any
 * special effort in system call implementation. */
static void
syscall_seek (int fd UNUSED, unsigned position UNUSED) {
	ASSERT (0);
}

/* Returns the position of the next byte to be read or written in open
* file fd, expressed in bytes from the beginning of the file. */
static unsigned
syscall_tell (int fd UNUSED) {
	ASSERT (0);
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly
 * closes all its open file descriptors, as if by calling this function
 * for each one. */
static void
syscall_close (int fd UNUSED) {
	ASSERT (0);
}

/* The dup2() system call creates a copy of the file descriptor oldfd with
 * the file descriptor number specified in newfd, and returns newfd on
 * success. If the file descriptor newfd was previously open, it is
 * silently closed before being reused.
 * Note the following points:
 * If oldfd is not a valid file descriptor, then the call fails (returns
 * -1), and newfd is not closed.
 * If oldfd is a valid file descriptor, and newfd has the same value as
 * oldfd, then dup2() does nothing, and returns newfd.
 * After a successful return from this system call, the old and new file
 * descriptors may be used interchangeably. Although they are different
 * file descriptors, they refer to the same open file description and thus
 * share file offset and status flags; for example, if the file offset is
 * modified by using seek on one of the descriptors, the offset is also
 * changed for the other. */
static int
syscall_dup2 (int oldfd UNUSED, int newfd UNUSED) {
	ASSERT (0);
}

static void
check_address (void *addr) {
	if (!is_user_vaddr(addr)) /* addr is not in user va. */
		syscall_exit (-1);
}

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
