#include "preloadcommon.h"

static long (*real_ptrace_p)();
static pid_t (*real_wait4)(pid_t pid, int *wstatus, int options, struct rusage *rusage);

#if 0
#define V(m, ...) fprintf(stderr, "side-strace-side: " m "\n" , ##__VA_ARGS__)
#else
#define V(...)
#endif

struct side_proc {
	struct wait4_result last_wait;
	struct side_proc *next;
	unsigned real_options;
	bool want_syscalls:1;
	bool configured:1;
	bool inside_syscall:1;
	bool inner_pending:1;
	bool outer_pending:1;
	bool enter_already_done:1;
	bool will_skip_sysexit:1;
	bool in_seccomp_handler:1;
};
static struct side_proc *proc_list;

struct side_connection {
	const char *socket_env_var;
	int fd;
};
static struct side_connection connection_inner = {
	.socket_env_var = "SIDESTRACE_SOCKET",
	.fd = -1
};
static struct side_connection connection_outer = {
	.socket_env_var = "SIDESTRACE_SOCKET_OUTER",
	.fd = -1
};

static long real_ptrace(request_type request, pid_t pid, void *addr, void *data) {
	if (real_ptrace_p == NULL) {
		real_ptrace_p = dlsym(RTLD_NEXT, "ptrace");
	}
	return real_ptrace_p(request, pid, addr, data);
}

static struct side_proc *proc_by_pid(pid_t pid, bool create) {
	struct side_proc *cur = proc_list;
	while (cur != NULL) {
		if (cur->last_wait.pid == pid) return cur;
		cur = cur->next;
	}
	if (create) {
		cur = calloc(1, sizeof(struct side_proc));
		cur->last_wait.pid = pid;
		cur->next = proc_list;
		proc_list = cur;
		return cur;
	}
	return NULL;
}
static void clear_proc_pid(pid_t pid) {
	struct side_proc **cur = &proc_list;
	while (*cur != NULL) {
		if ((*cur)->last_wait.pid == pid) {
			free(*cur);
			*cur = (*cur)->next;
			return;
		}
		cur = &(*cur)->next;
	}
}

static void connect_socket_if_needed(struct side_connection *connection)
{
	if (connection->socket_env_var == NULL)
		return;

	struct sockaddr_un addr = {
		.sun_family = AF_UNIX
	};
	const char *path = getenv(connection->socket_env_var);
	connection->socket_env_var = NULL;
	if (path == NULL) {
		return;
	}

	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	connection->fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	fcntl(connection->fd, F_SETFL, O_CLOEXEC);
	int ret = connect(connection->fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0) {
		perror("side-strace-side: connect");
		abort();
	}
}

static void trap_to_strace(struct side_proc *proc, struct side_connection *connection) {
	connect_socket_if_needed(connection);
	V("trap_to_strace fd=%d", connection->fd);
	if (connection->fd == -1) {
		return;
	}
	int r = write(connection->fd, &proc->last_wait, sizeof(struct wait4_result));
	if (r <= 0) { perror("side-strace-side: initial write"); abort(); }
	if (WIFEXITED(proc->last_wait.wstatus) || WIFSIGNALED(proc->last_wait.wstatus)) {
		clear_proc_pid(proc->last_wait.pid);
		return;
	}
	for (;;) {
		struct side_strace_rpc req = {};
		read(connection->fd, &req, sizeof(struct side_strace_rpc));
		switch (req.cmd) {
		case CMD_CONT:
			return;
		case CMD_GETSIGINFO: {
			siginfo_t siginfo;
			real_ptrace(PTRACE_GETSIGINFO, proc->last_wait.pid, NULL, &siginfo);
			write(connection->fd, &siginfo, sizeof(siginfo_t));
			break;
		}
		case CMD_GETREGSET: {
			char data[req.getregset.size];
			struct iovec iov = {
				.iov_len = req.getregset.size,
				.iov_base = data
			};
			long ret = real_ptrace(PTRACE_GETREGSET, proc->last_wait.pid, req.getregset.type, &iov);
#ifdef __i386__
			if (ret == -1 && req.getregset.type == 0 && req.getregset.size == sizeof(struct user_regs_struct))
			{
				ret = real_ptrace(PTRACE_GETREGS, proc->last_wait.pid, NULL, data);
			}
#endif
			if (ret == -1) {
				perror("side-strace-side: ptrace(PTRACE_GETREGSET)");
				abort();
			}
			write(connection->fd, data, req.getregset.size);
			break;
		}
		case CMD_GETEVENTMSG:
		{
			unsigned long msg = 0;
			real_ptrace(PTRACE_GETEVENTMSG, proc->last_wait.pid, NULL, &msg);
			write(connection->fd, &msg, sizeof(unsigned long));
			break;
		}
		case CMD_PEEKDATA:
		{
			long data = 0;
			data = real_ptrace(PTRACE_PEEKDATA, proc->last_wait.pid, req.peekdata.addr, 0);
			write(connection->fd, &data, sizeof(long));
			break;
		}
		}
	}
}

#include <assert.h>
static void trap_on_continue(struct side_proc *proc) {
	V("trap_on_continue will_skip_sysexit=%d inside_syscall=%d", proc->will_skip_sysexit, proc->inside_syscall);
	if (proc->will_skip_sysexit && proc->in_seccomp_handler) {
		V("(Seccomp skip - fake enter)");
		// Emulate receiving SIGTRAP|0x80 for syscall enter
		proc->inside_syscall = true; // Next event is syscall exit
		assert(proc->will_skip_sysexit);
		proc->will_skip_sysexit = false;
		assert(!proc->inner_pending);
		proc->inner_pending = false; // Won't be dispatched
		assert(!proc->outer_pending);
		proc->outer_pending = false; // Should be already false
		assert(proc->enter_already_done);
		proc->enter_already_done = false;
		trap_to_strace(proc, &connection_inner); // Do now as we skip SIGTRAP
#if 0
	} else if (proc->will_skip_sysexit && proc->inside_syscall) {
		V("(Sysexit skip)");
		assert(proc->inside_syscall);
		//proc->inside_syscall = false;
		assert(proc->will_skip_sysexit);
		proc->will_skip_sysexit = false;
		assert(proc->inner_pending);
		proc->inner_pending = false; // Won't be dispatched
		assert(!proc->outer_pending);
		proc->outer_pending = false; // Should be already false
		assert(proc->enter_already_done);
		proc->enter_already_done = false;
#if 0
		trap_to_strace(proc, &connection_inner);
		trap_to_strace(proc, &connection_inner);
#endif
		//trap_to_strace(proc, &connection_outer);
#endif
	} else {
		V("(Normal)");
		proc->will_skip_sysexit = false;
		if (proc->inner_pending) {
			trap_to_strace(proc, &connection_inner);
			proc->inner_pending = false;
		}
		if (proc->outer_pending) {
			trap_to_strace(proc, &connection_outer);
			proc->outer_pending = false;
		}
	}
}

long ptrace(request_type request, pid_t pid, void *addr, void *data)
{
	int saved_errno = errno;
	if (request == PTRACE_TRACEME) {
		unsetenv("LD_PRELOAD");
	} else {
		struct side_proc *proc = proc_by_pid(pid, true);
		if (!proc->configured && request != PTRACE_SETOPTIONS && request != PTRACE_SEIZE) {
			real_ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)PTRACE_O_TRACESYSGOOD);
			proc->configured = true;
		}
		switch (request) {
		case PTRACE_SYSCALL:
			proc->want_syscalls = true;
			trap_on_continue(proc);
			break;
		case PTRACE_CONT:
			proc->want_syscalls = false;
			trap_on_continue(proc);
			request = PTRACE_SYSCALL;
			break;
		case PTRACE_SETOPTIONS:
		case PTRACE_SEIZE:
			proc->real_options = (unsigned)(unsigned long)data;
			proc->configured = true;
			data = (void*)((long)data | PTRACE_O_TRACESYSGOOD);
			break;
#ifdef __aarch64__
		case PTRACE_SETREGSET:
			if (addr == (void*)0x404) { // NT_ARM_SYSTEM_CALL
				struct iovec *iov = data;
				long value = *(long*)iov->iov_base;
				if (proc->in_seccomp_handler) {
					proc->will_skip_sysexit = (value < 0);
				} else {
					proc->will_skip_sysexit = (value == -1);
				}
				V("PTRACE_SetRegSet NT_ARM_SYSTEM_CALL value=%ld will_skip_sysexit=%d", value, proc->will_skip_sysexit);
			}
			break;
#endif
		default:
			break;
		}
	}
	errno = saved_errno;
	return real_ptrace(request, pid, addr, data);
}

pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage) {
	if (real_wait4 == NULL) {
		real_wait4 = dlsym(RTLD_NEXT, "wait4");
	}

	struct rusage local_rusage = {};
	int local_wstatus = 0;
	if (rusage == NULL) rusage = &local_rusage;
	if (wstatus == NULL) wstatus = &local_wstatus;

	for (;;) {
		pid_t result = real_wait4(pid, wstatus, options, rusage);
		V("Received pid=%d wstatus=0x%x", result, *wstatus);
		if (result != -1 && result != 0) {
			bool is_ptrace_stop = WIFSTOPPED(*wstatus);
			if (is_ptrace_stop && (options & WSTOPPED)) {
				int saved_errno = errno;
				real_ptrace(PTRACE_GETREGSET, result, (void*)-1, NULL);
				is_ptrace_stop = (errno != ESRCH);
				errno = saved_errno;
			}
			struct side_proc *proc = proc_by_pid(result, is_ptrace_stop);
			if (proc == NULL) return result;
			proc->last_wait.wstatus = *wstatus;
			proc->last_wait.options = options;
			proc->last_wait.rusage = *rusage;
			proc->in_seccomp_handler = false;
			if (*wstatus == ((SIGTRAP | 0x80) << 8 | 0x7f)) {
				if (proc->inside_syscall ^= 1) {
					V("Syscall enter");
					if (!proc->enter_already_done) {
						proc->enter_already_done = true;
						trap_to_strace(proc, &connection_outer);
					}
					proc->inner_pending = true;
				} else {
					V("Syscall exit");
					trap_to_strace(proc, &connection_inner);
					proc->outer_pending = true;
					proc->enter_already_done = false;
				}
				if (!proc->want_syscalls) {
					V("Suppress wstatus 0x%x", *wstatus);
					trap_on_continue(proc);
					real_ptrace(PTRACE_SYSCALL, result, NULL, NULL);
					continue;
				}
				if (!(proc->real_options & PTRACE_O_TRACESYSGOOD)) {
					V("Strip 0x80 from SIGTRAP wstatus 0x%x", *wstatus);
					*wstatus &= ~(0x80 << 8);
				}
			} else if (*wstatus == ((SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)) << 8 | 0x7f)) {
				proc->in_seccomp_handler = true;
				V("Seccomp event");
				if (!proc->enter_already_done) {
					proc->enter_already_done = true;
					proc->last_wait.wstatus = ((SIGTRAP | 0x80) << 8 | 0x7f);
					trap_to_strace(proc, &connection_outer);
				}
			} else if (
					*wstatus == ((SIGTRAP | (PTRACE_EVENT_CLONE << 8)) << 8 | 0x7f) ||
					*wstatus == ((SIGTRAP | (PTRACE_EVENT_FORK  << 8)) << 8 | 0x7f) ||
					*wstatus == ((SIGTRAP | (PTRACE_EVENT_VFORK << 8)) << 8 | 0x7f)
					) {
				unsigned long new_pid = 0;
				real_ptrace(PTRACE_GETEVENTMSG, result, 0, &new_pid);
				struct side_proc *new_proc = proc_by_pid((pid_t) new_pid, true);
				new_proc->real_options = proc->real_options;
				new_proc->configured = true;
			} else {
				trap_to_strace(proc, &connection_inner);
				trap_to_strace(proc, &connection_outer);
			}
		}
		V("Deliver pid=%d wstatus=0x%x", result, *wstatus);
		return result;
	}
}

pid_t wait(int *wstatus) { return wait4(-1, wstatus, 0, NULL); }

pid_t waitpid(pid_t pid, int *wstatus, int options) { return wait4(pid, wstatus, options, NULL); }
