#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <list.h>
#include "threads/thread.h"

/* Structure that holds the information of a terminated child process.
   This structure is created when such termination occurs and then added
   to its parent process' terminated_children_st list, so that the child
   information (id and exit status) can be retrieved later using wait(). */
struct terminated_child_st {
  tid_t pid;
  int exit_status;
  struct list_elem elem;
};

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

#endif /* userprog/process.h */
