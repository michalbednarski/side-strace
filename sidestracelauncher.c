#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/wait.h>

#define SILENCE_STRACE_SERVER 1
#define IGNORE_SIGINT 1

static pid_t launch_strace_server(const char *outputFile, const char *socket, const char *lib) {
	bool serverReady;
	bool serverFailure;
	pid_t pid = fork();
	if (pid == 0) {
#if SILENCE_STRACE_SERVER
		int devNull = open("/dev/null", O_RDWR);
		dup2(devNull, 0);
		dup2(devNull, 1);
		dup2(devNull, 2);
		close(devNull);
#endif
#if IGNORE_SIGINT
		setsid();
#endif
		setenv("SIDESTRACE_SOCKET", socket, 1);
		setenv("LD_PRELOAD", lib, 1);
		execlp("strace", "strace", "-fp1", "-o", outputFile, NULL);
		_exit(0);
	}
	if (pid != -1) {
		do {
			usleep(250);
			serverReady = (0 == access(socket, F_OK));
			serverFailure = (pid == waitpid(pid, NULL, WNOHANG));
		} while (!(serverReady || serverFailure));
		if (serverFailure) {
			pid = -1;
		}
	}
	return pid;
}

int main(int argc, char **argv) {
	int i = 1;
	char *innerOutput = NULL;
	char *outerOutput = NULL;
	char innerTraceSocket[100] = {};
	pid_t innerTraceServer = -1;
	char outerTraceSocket[100] = {};
	pid_t outerTraceServer = -1;
	pid_t sidePid = -1;
	char soStrace[PATH_MAX] = {};
	char soSide[PATH_MAX] = {};
	ssize_t linkSize;
	int exitStatus = 0x100;
	bool noFork = false;

	// Find .so files
	linkSize = readlink("/proc/self/exe", soStrace, sizeof(soStrace) - 1);
	if (!(linkSize > 0 && linkSize < sizeof(soStrace) - 1)) {
		fprintf(stderr, "sidestrace: Unexpected readlink /proc/self/exe result\n");
		return 1;
	}
	soStrace[linkSize] = '\0';
	char *dirNameResult = dirname(soStrace);
	memmove(soStrace, dirNameResult, strlen(dirNameResult) + 1);
	strcpy(soSide, soStrace);
	strncat(soStrace, "/sidestracestrace.so", sizeof(soStrace) - 1);
	strncat(soSide, "/sidestraceside.so", sizeof(soSide) - 1);
	if (0 != access(soStrace, F_OK) || 0 != access(soSide, F_OK)) {
		fprintf(stderr, "sidestrace: Unable to locate libraries\n");
		return 1;
	}

	// Parse args
	for (;i < argc;) {
		if (0 == strcmp("-o", argv[i])) {
			innerOutput = argv[i + 1];
			i += 2;
		} else if (0 == strcmp("-O", argv[i])) {
			outerOutput = argv[i + 1];
			i += 2;
		} else if (0 == strcmp("-n", argv[i])) {
			noFork = true;
			i += 1;
		} else {
			break;
		}
	}
	if (innerOutput == NULL && outerOutput == NULL) {
		fprintf(stderr, "No output specified\n");
	}
	if (innerOutput != NULL) {
		strcpy(innerTraceSocket, "sct_side_strace_socket_iXXXXXX");
		mktemp(innerTraceSocket);
		innerTraceServer = launch_strace_server(innerOutput, innerTraceSocket, soStrace);
		if (innerTraceServer == -1) {
			fprintf(stderr, "sidestrace: strace server failed to start\n");
			return 1;
		}
	}
	if (outerOutput != NULL) {
		strcpy(outerTraceSocket, "sct_side_strace_socket_oXXXXXX");
		mktemp(outerTraceSocket);
		outerTraceServer = launch_strace_server(outerOutput, outerTraceSocket, soStrace);
		if (outerTraceServer == -1) {
			fprintf(stderr, "sidestrace: strace server failed to start\n");
			return 1;
		}
	}

	// Launch side
	if (!noFork) {
		sidePid = fork();
	}
#if IGNORE_SIGINT
	else {
		signal(SIGINT, SIG_IGN);
	}
#endif
	if (sidePid == 0 || noFork) {
		setenv("LD_PRELOAD", soSide, 1);
		if (innerOutput != NULL) setenv("SIDESTRACE_SOCKET"      , innerTraceSocket, 1);
		if (outerOutput != NULL) setenv("SIDESTRACE_SOCKET_OUTER", outerTraceSocket, 1);
		execvp(argv[i], argv + i);
		_exit(1);
	}
	waitpid(sidePid, &exitStatus, 0);

	// Cleanup after side has exited
	if (innerTraceServer != -1) {
		kill(innerTraceServer, SIGINT);
		waitpid(innerTraceServer, NULL, 0);
	}
	if (innerTraceSocket[0] != '\0') {
		unlink(innerTraceSocket);
	}
	if (outerTraceServer != -1) {
		kill(outerTraceServer, SIGINT);
		waitpid(outerTraceServer, NULL, 0);
	}
	if (outerTraceSocket[0] != '\0') {
		unlink(outerTraceSocket);
	}

	if (WIFEXITED(exitStatus)) {
		return WEXITSTATUS(exitStatus);
	}
	return 1;
}
