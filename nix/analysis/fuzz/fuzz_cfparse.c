/*
 * libFuzzer harness for the mcd.conf parser: the hand-written lexer and
 * the yacc grammar in src/cfparse.y, through config_init() as main.c
 * calls it, including the config_iface_*() calls the grammar makes.
 *
 * The generated parser is included rather than linked so the harness can
 * reach its static state. fatal() and yyerror() exit(); the exit() wrapper
 * longjmps back here, after which the harness closes the file the parser
 * left open and drains the lexer's static line buffer, so every input
 * starts from a clean parser.
 *
 * SPDX-License-Identifier: ISC
 */

#include "cfparse.c"

#include <sys/mman.h>

#include "fuzz_harness.h"

static FILE *devnull;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	fuzz_init();
	devnull = fopen("/dev/null", "r");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static char path[64];
	int fd;

	fd = memfd_create("mcd.conf", 0);
	if (fd < 0)
		abort();
	if (size && write(fd, data, size) != (ssize_t)size)
		abort();
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	config_file = path;

	if (setjmp(fuzz_exit_jmp) == 0) {
		fuzz_exit_armed = 1;
		config_init();
	}
	fuzz_exit_armed = 0;

	/* After a fatal() the parser never got to fclose() its file. */
	if (yyin) {
		fclose(yyin);
		yyin = NULL;
	}
	/* ... and yytoken() may still hold the rest of the line it was on. */
	yyin = devnull;
	while (yytoken())
		;
	rewind(devnull);
	yyin = NULL;
	ifi = twin = NULL;

	fuzz_iface_down();
	close(fd);

	return 0;
}
