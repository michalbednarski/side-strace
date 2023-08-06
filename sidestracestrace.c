#include "preloadcommon.h"
#include <signal.h>
#include <sys/user.h>
#include <sys/epoll.h>

static int server_side_strace_socket = -1;
static int side_strace_epoll = -1;

static int side_strace_socket = -1;
static pid_t current_stopped_pid = -1;

static pid_t (*real_wait4)(pid_t pid, int *wstatus, int options, struct rusage *rusage);

#define REQ(...) {\
	struct side_strace_rpc req = {__VA_ARGS__};\
	write(side_strace_socket, &req, sizeof(struct side_strace_rpc));\
}

#if 0
#define V(m, ...) fprintf(stderr, "side-strace-strace: " m "\n" , ##__VA_ARGS__)
#else
#define V(...)
#endif

static void __attribute__((constructor)) init()
{
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX
	};
	strncpy(addr.sun_path, getenv("SIDESTRACE_SOCKET"), sizeof(addr.sun_path));
	server_side_strace_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (server_side_strace_socket < 0) {
		perror("side-strace-strace: socket");
		abort();
	}
	fcntl(server_side_strace_socket, F_SETFL, O_CLOEXEC);
	
	int ret = bind(server_side_strace_socket, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0) {
		perror("side-strace-strace: bind");
		abort();
	}
	listen(server_side_strace_socket, 1);

	side_strace_epoll = epoll_create1(EPOLL_CLOEXEC);
	if (side_strace_epoll < 0) {
		perror("side-strace-strace: epoll_create1");
		abort();
	}

	struct epoll_event eevt = {
		.events = EPOLLIN,
		.data = { .fd = server_side_strace_socket }
	};
	epoll_ctl(side_strace_epoll, EPOLL_CTL_ADD, server_side_strace_socket, &eevt);

	unsetenv("LD_PRELOAD");
	real_wait4 = dlsym(RTLD_NEXT, "wait4");
	if (real_wait4 == NULL) {
		fprintf(stderr, "side-strace-strace: dlsym(wait4): %s\n", dlerror());
		abort();
	}
}

static bool wait_for_request(struct wait4_result *request) {
	for (;;)
	{
		struct epoll_event eevt = {};
		int ret = epoll_wait(side_strace_epoll, &eevt, 1, -1);
		if (ret != 1) {
			if (errno == EINTR) return false;
			perror("side-strace-strace: epoll_wait");
			abort();
		}
		if (eevt.data.fd == server_side_strace_socket) {
			struct sockaddr_un client_addr = { .sun_family = AF_UNIX };
			socklen_t client_addr_len = sizeof(client_addr);
			int csock = accept(server_side_strace_socket, (struct sockaddr *)&client_addr, &client_addr_len);
			if (csock < 0) {
				perror("side-strace-strace: accept");
				abort();
			}
			fcntl(csock, F_SETFL, O_CLOEXEC);
			struct epoll_event neevt = {
				.events = EPOLLIN,
				.data = { .fd = csock }
			};
			epoll_ctl(side_strace_epoll, EPOLL_CTL_ADD, csock, &neevt);
			
		} else {
			int readres = read(eevt.data.fd, request, sizeof(struct wait4_result));
			if (readres == 0) {
				epoll_ctl(side_strace_epoll, EPOLL_CTL_DEL, eevt.data.fd, NULL);
				close(eevt.data.fd);
			} else {
				if (readres != sizeof(struct wait4_result)) {
					perror("side-strace-strace: wait_for_request read");
					abort();
				}
				side_strace_socket = eevt.data.fd;
				current_stopped_pid = request->pid;
				return true;
			}
		}
	}
}

long ptrace(request_type request, pid_t pid, void *addr, void *data)
{
	switch (request) {
		//case PTRACE_ATTACH:
		case PTRACE_SEIZE:
			V("seize pid=%d", pid);
			errno = 0;
			return 0;
		case PTRACE_INTERRUPT:
			V("interrupt");
			return 0;
		case PTRACE_DETACH:
			V("detatch pid=%d", pid);
			return 0;
		case PTRACE_GETREGSET:
			{
			struct iovec *iov = data;
			REQ( .cmd = CMD_GETREGSET, .getregset = { .type = addr, .size = iov->iov_len});
			read(side_strace_socket, iov->iov_base, iov->iov_len);
			V("getregset=%p", addr);
			return 0;
			}
#ifdef __i386__
		case PTRACE_GETREGS:
			{
			REQ( .cmd = CMD_GETREGSET, .getregset = { .type = 0, .size = sizeof(struct user_regs_struct)});
			read(side_strace_socket, data, sizeof(struct user_regs_struct));
			V("getregs");
			return 0;
			}
#endif
		case PTRACE_GETSIGINFO:
			REQ( .cmd = CMD_GETSIGINFO );
			read(side_strace_socket, data, sizeof(siginfo_t));
			return 0;
		case PTRACE_GETEVENTMSG:
			REQ( .cmd = CMD_GETEVENTMSG );
			read(side_strace_socket, data, sizeof(unsigned long));
			return 0;
		case PTRACE_PEEKDATA:
		{
			REQ( .cmd = CMD_PEEKDATA, .peekdata = { .addr = addr } );
			long res;
			read(side_strace_socket, &res, sizeof(long));
			return res;
		}
		case PTRACE_SYSCALL:
		case PTRACE_LISTEN: // Normally keeps tracee stopped after SIGSTOP
		case PTRACE_CONT:
			REQ( .cmd = CMD_CONT );
			side_strace_socket = -3;
			return 0;
		default:
			fprintf(stderr, "side-strace-strace: Unknown ptrace() request=0x%x\n", request);
			abort();
	}
	return 0;
}

pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage) {
	V("side-strace-strace: wait enter %d", pid);
	if ((options & WNOHANG) != 0 && side_strace_socket >= 0) {
		V("Ignoring wait4 batching by strace", pid);
		errno = ECHILD;
		return -1;
	}
	pid_t real_result = real_wait4(pid, wstatus, options, rusage);
	if (!(real_result == -1 && errno == ECHILD)) {
		side_strace_socket = -2;
		return real_result;
	}
	struct wait4_result result = {};
	if (wait_for_request(&result)) {
		if (wstatus != NULL) *wstatus = result.wstatus;
		if (rusage != NULL) *rusage = result.rusage;
		V("wait exit %d", result.pid);
		return result.pid;
	} else {
		errno = EINTR;
		return -1;
	}
}
