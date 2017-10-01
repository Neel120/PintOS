#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/fixed.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* List of all processes in THREAD_BLOCKED state, that is,
   processes which don't want to use the processor until their
   wakeup_time. */
static struct list sleepers_list;

/* List of already finished processes to allow for wait system
   call to be implemented. */
static struct list dead_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Lock for file system access by User Programs. */
//static struct lock filesys_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Structure for processes which have finished execution. */
struct dead_thread 
  {
    tid_t tid;
    tid_t ptid;
    int exit_status;
    struct list_elem dead_elem;
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */
static long long all_ticks;
static long long next_wakeup_time;
static long long load;
/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static void wakeup_thread (void *aux UNUSED);
static void recompute (void * aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static struct thread *wu_thread;
static struct thread *decay_thread;
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);
/* Comparator to use with the ready list for priority scheduling. */
static bool priocmp (const struct list_elem *a, const struct list_elem *b, void * aux UNUSED)
{
  return list_entry(a,struct thread, elem)->priority > list_entry(b,struct thread, elem)->priority;
}

/* Comparator to use with the sleepers list. */
static bool wakeup_compare(const struct list_elem *a, const struct list_elem *b, void * aux UNUSED)
{
  return list_entry(a,struct thread, elem)->wakeup_time < list_entry(b,struct thread, elem)->wakeup_time;
}

int waiter(tid_t child_tid){
    enum intr_level old_level = intr_disable();
    struct list_elem * e;
    struct dead_thread * dt;
    for(e=list_begin(&dead_list);e!=list_end(&dead_list);e=list_next(e))
    {
      dt = list_entry(e,struct dead_thread, dead_elem);
      if(dt->tid==child_tid){
        intr_set_level(old_level);
        
        if(dt->ptid!=thread_current ()->tid)
          return -1;
        
        int x = dt->exit_status;
        list_remove(e);
        free(dt);
        return x;
      }
    }
    struct thread * t;
    for(e = list_begin(&all_list);e!=list_end(&all_list);e=list_next(e))
    {
      t=list_entry(e,struct thread, allelem);
      if(t->tid==child_tid)
      {
        list_push_back(&(t->waiters),&(thread_current ()->elem));
        thread_block();  
        int x = thread_current ()->waitret;
        thread_current ()->waitret = 0;
        intr_set_level(old_level);
        return x;    
      }
    }
    intr_set_level(old_level);
    return -1;
}

void test_stack(int *t)
{ 
  int i;
  int argc = t[1];
  char ** argv;
  argv = (char **) t[2];
  printf("ARGC:%d  ARGV:%x\n", argc, (unsigned int)argv);
  for (i = 0; i < argc; i++)
    printf("Argv[%d] = %x pointing at %s\n", i, (unsigned int)argv[i], argv[i]);
}

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  list_init (&sleepers_list);
  list_init (&dead_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
  next_wakeup_time = 1e18;
  load = 0;
  all_ticks = 0;
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);
  wu_thread = thread_create_2("wakeup", PRI_MAX, wakeup_thread,NULL);
  if(thread_mlfqs)
    decay_thread = thread_create_2("decay", PRI_MAX, recompute, NULL);
  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

void
recent_cpu_recalculate(struct thread * t)
{
  int z = 2*load;
  t->recent_cpu = INT_ADD (FP_MUL (FP_DIV (z, INT_ADD (z, 1)), t->recent_cpu), t->niceness);
  t->priority = (PRI_MAX) - CONVERT_TO_INT_ZERO(t->recent_cpu/4) - (2*t->niceness);
  if(t->priority<PRI_MIN)
    t->priority = PRI_MIN;
  if(t->priority>PRI_MAX)
    t->priority = PRI_MAX;
  //thread_check_yield();
}

void
recompute (void * aux UNUSED)
{
  while(1)
  {
    struct list_elem * e;

    for(e = list_begin(&all_list); e!=list_end(&all_list); e = list_next(e))
    {
      struct thread* t = list_entry(e, struct thread, allelem);
      if(t==idle_thread || t==wu_thread || t==decay_thread)
        continue;
      recent_cpu_recalculate(t);      
    }
    
    int x = list_size(&ready_list);
    for(e = list_begin(&ready_list); e!=list_end(&ready_list); e = list_next(e))
    {
      tid_t id = list_entry(e,struct thread, elem)->tid;
      if(id == wu_thread->tid || id==decay_thread->tid || id==idle_thread->tid)
        x--;
    }
    load = FP_MUL (CONVERT_TO_FP (59) / 60, load) + CONVERT_TO_FP (1) / 60 * x;

    list_sort(&ready_list,priocmp,NULL);
    enum intr_level old_level = intr_disable();
    thread_block();
    intr_set_level(old_level);
  }
}
/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (int64_t timer_ticks, int64_t freq) 
{
  struct thread *t = thread_current ();
  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  all_ticks = timer_ticks;

  if(thread_mlfqs)
  {
    t->recent_cpu = INT_ADD(t->recent_cpu,1);
    if(t!=idle_thread && t!=decay_thread && t!=wu_thread)
    {
      if(all_ticks%TIME_SLICE==0)
      {
        t->priority = (PRI_MAX) - CONVERT_TO_INT_ZERO(t->recent_cpu/4) - (2*t->niceness);
        if(t->priority<PRI_MIN)
          t->priority = PRI_MIN;
        if(t->priority>PRI_MAX)
          t->priority = PRI_MAX;
      }
    }

    if(all_ticks%freq==0 && decay_thread->status==THREAD_BLOCKED)
    {
      thread_unblock(decay_thread);
      intr_yield_on_return();
    }
  }
  
  if(wu_thread->status==THREAD_BLOCKED && all_ticks>=next_wakeup_time)
  {
    thread_unblock(wu_thread);
    intr_yield_on_return();
  }

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE && t!=wu_thread && t!=decay_thread)
  {
    intr_yield_on_return ();
  }

}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  t->parent_thread = thread_current ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;
  //printf("Created Thread : %s\n", name);
  intr_set_level (old_level);
  /* Add to run queue. */
  thread_unblock (t);
  thread_priority_restore();
  thread_check_yield();
  return tid;
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
struct thread * 
thread_create_2 (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return t;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  next_wakeup_time=1e18;
  intr_set_level (old_level);
  thread_unblock(t);
  return t;
}

/* Putting a sleeping thread into the sleepers list*/
void
thread_sleep(int64_t wakeup_time,int64_t timer_ticks)
{
  enum intr_level old_level;
  old_level = intr_disable();
  struct thread * cur = thread_current ();
  if(wakeup_time<timer_ticks)
    return;
  ASSERT(cur->status == THREAD_RUNNING);
  cur->wakeup_time = wakeup_time;
  if(next_wakeup_time>wakeup_time)
    next_wakeup_time = wakeup_time;
  list_insert_ordered(&sleepers_list, &cur->elem, wakeup_compare, NULL);
  thread_block();
  intr_set_level(old_level);
}

/* Procedure to execute when a wakeup happens*/
bool
thread_wakeup(int64_t timer_ticks)
{
  if(list_empty(&sleepers_list))
    return 0;
  
  struct thread * t = list_entry(list_begin(&sleepers_list),struct thread,elem);
  if(timer_ticks<t->wakeup_time)
    return 0;

  list_pop_front(&sleepers_list);
  thread_unblock(t);
  return 1;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_insert_ordered (&ready_list, &t->elem, priocmp,NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (int status) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
  printf("%s: exit(%d)\n", thread_current ()->name, status);
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it call schedule_tail(). */

  intr_disable ();
  struct list_elem * e;
  struct thread * t = thread_current ();

  close_all_files(t);

  if(list_size(&(t->waiters)))
  {
    for(e = list_begin(&(t->waiters)); e != list_end(&(t->waiters)); e = list_begin(&(t->waiters))){
      struct thread * t2 = list_entry(e, struct thread, elem);
      list_remove(e);
      t2->waitret = status;
      thread_unblock(t2);
    }
  }
  else{
    struct dead_thread * dt = malloc(sizeof(struct dead_thread));
    dt->tid = t->tid;
    dt->exit_status = status;
    dt->ptid = t->parent_thread->tid;
    list_push_back(&dead_list,&(dt->dead_elem));  
  }
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
    list_insert_ordered (&ready_list, &cur->elem,priocmp,NULL);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

void
priority_donate()
{
  if(thread_mlfqs)
    return ;

  enum intr_level old_level = intr_disable();
  struct thread * t= thread_current ();
  struct lock * l = thread_current ()->seeking;
  while(l)
  {
    if(l->holder==NULL)
      break;
    if(l->holder->priority >= t->priority)
      break;
    l->holder->priority = t->priority;
    t = l->holder;
    l = t->seeking;
  }
  list_sort(&ready_list,priocmp,NULL);
  intr_set_level(old_level);
}

/*  This function is called when the priority of the current thread
    changes or a new thread get added to the ready list. The function
    checks whether a higher priority thread is in the ready list and
    if this is the case, the current thread yields the processor.  */
void
thread_check_yield(void)
{
  enum intr_level old_level = intr_disable();
  if(!list_empty(&ready_list) && list_entry(list_front(&ready_list),struct thread, elem)->priority > thread_current()->priority)
    thread_yield();
  intr_set_level(old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  if(thread_mlfqs)
    return;

  int prio = thread_current ()->priority;
  thread_current ()->temp_priority = new_priority;
  thread_priority_restore();
  if(prio < thread_current()->priority)
  {
    priority_donate ();
  }
  thread_check_yield();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  struct thread * t = thread_current ();
  t->niceness = nice;
  recent_cpu_recalculate(t);
  t->priority = (PRI_MAX) - CONVERT_TO_INT_NEAR(t->recent_cpu/4) - (2*t->niceness);
  if(t->priority < PRI_MIN)
    t->priority = PRI_MIN;
  if(t->priority > PRI_MAX)
    t->priority = PRI_MAX;
  thread_check_yield ();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  //return 0;
  return thread_current ()->niceness;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  return CONVERT_TO_INT_NEAR(load*100);
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  return CONVERT_TO_INT_NEAR(thread_current()->recent_cpu*100);
}

/* Restores the priority of the thread. Checks for the donation of priorities. */
int
thread_priority_restore(void)
{
  if(thread_mlfqs)
    return 0;
  int prio = thread_current()->temp_priority;
  enum intr_level old_level = intr_disable();
  struct list_elem * e = list_begin(&thread_current ()->locks_acquired);
  while(e!=list_end(&thread_current ()->locks_acquired))
  {
    struct lock * l = list_entry(e,struct lock,elem);
    struct list_elem * e2 = list_begin(&l->semaphore.waiters);
    while(e2!=list_end(&l->semaphore.waiters))
    {
      int x = list_entry(e2,struct thread,elem)->priority;
      if(x>prio)
        prio=x;
      e2 = list_next(e2);
    }
    e = list_next(e);
  }
  thread_current() -> priority = prio;
  list_sort(&ready_list,priocmp,NULL);
  intr_set_level(old_level);
  thread_check_yield();
  return prio;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

static void
wakeup_thread (void *aux UNUSED)
{
  while(1)
  {
    if(list_empty(&sleepers_list))
    {
      enum intr_level old_level = intr_disable();
      next_wakeup_time=1e18;
      thread_block();
      intr_set_level(old_level);
      continue;
    }
    
    struct thread * t = list_entry(list_begin(&sleepers_list),struct thread,elem);
    if(all_ticks<t->wakeup_time)
    {
      enum intr_level old_level = intr_disable();
      next_wakeup_time = t->wakeup_time;
      thread_block();
      intr_set_level(old_level);
      continue;
    }

    list_pop_front(&sleepers_list);
    thread_unblock(t);
  }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit (0);       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->temp_priority = priority;
  t->magic = THREAD_MAGIC;
  t->niceness = 0;
  t->recent_cpu = 0;
  t->waitret = 0;
  list_init(&(t->waiters));
  list_init(&(t->files));
  sema_init(&(t->childlock),0);
  t->fd_last = 2;
  if(thread_mlfqs)
  {
    t->temp_priority = t->priority = PRI_MAX;   
  }
  t->seeking = NULL;
  list_init(&(t->locks_acquired));
  list_push_back (&all_list, &t->allelem);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
schedule_tail (struct thread *prev) 
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until schedule_tail() has
   completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  schedule_tail (prev); 
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
