#define _GNU_SOURCE
#define ptrace def_ptrace
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#undef ptrace

#ifdef __ANDROID__
#define request_type int
#else
#define request_type enum __ptrace_request
#endif

/* side->strace initial request */
struct wait4_result {
	pid_t pid;
	int wstatus;
	int options;
	struct rusage rusage;
};

/* strace->side request */
struct side_strace_rpc {
	enum {
		CMD_CONT = 1,
		CMD_GETSIGINFO,
		CMD_GETREGSET,
		CMD_GETEVENTMSG,
		CMD_PEEKDATA
	} cmd;
	union {
		struct {
			void *type;
			size_t size;
		} getregset;
		struct {
			void *addr;
		} peekdata;
	};
};
