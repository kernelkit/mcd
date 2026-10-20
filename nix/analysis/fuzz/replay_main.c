/*
 * A plain main() for the fuzz harnesses, used by checks.fuzz-replay: it
 * feeds every file named on the command line (directories are walked one
 * level) to LLVMFuzzerTestOneInput() once. Built with gcc and no libFuzzer,
 * it keeps every harness compiling and its seed corpus crash-free under
 * ASan/UBSan, without needing clang's fuzzer runtime.
 *
 * SPDX-License-Identifier: ISC
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "fuzz_harness.h"

#pragma weak LLVMFuzzerInitialize

static int run_file(const char *path)
{
	uint8_t *buf;
	long len;
	FILE *fp;

	fp = fopen(path, "rb");
	if (!fp || fseek(fp, 0, SEEK_END) || (len = ftell(fp)) < 0) {
		perror(path);
		return 1;
	}
	rewind(fp);

	buf = malloc(len ? (size_t)len : 1);
	if (!buf || fread(buf, 1, (size_t)len, fp) != (size_t)len) {
		perror(path);
		return 1;
	}
	fclose(fp);

	LLVMFuzzerTestOneInput(buf, (size_t)len);
	free(buf);

	return 0;
}

int main(int argc, char *argv[])
{
	int rc = 0, runs = 0;

	if (LLVMFuzzerInitialize)
		LLVMFuzzerInitialize(&argc, &argv);

	for (int i = 1; i < argc; i++) {
		struct stat st;

		if (stat(argv[i], &st)) {
			perror(argv[i]);
			return 1;
		}

		if (S_ISDIR(st.st_mode)) {
			struct dirent *d;
			DIR *dir = opendir(argv[i]);

			while (dir && (d = readdir(dir))) {
				char path[4096];

				if (d->d_name[0] == '.')
					continue;
				snprintf(path, sizeof(path), "%s/%s", argv[i], d->d_name);
				rc |= run_file(path);
				runs++;
			}
			if (dir)
				closedir(dir);
		} else {
			rc |= run_file(argv[i]);
			runs++;
		}
	}

	printf("replayed %d input(s)\n", runs);
	return rc || !runs;
}
