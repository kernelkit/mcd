/*
 * semgrep rule test for strtok-result-unchecked (nix/analysis/semgrep-rules.yaml).
 *
 * Run by nix/analysis/semgrep.nix as `semgrep --test`: a `ruleid:` comment
 * says the next line must be reported, an `ok:` comment says it must not.
 * Each case is labelled with its category and the outcome it expects.
 */
#include <stdlib.h>
#include <string.h>

size_t strlcpy(char *dst, const char *src, size_t len);

/* positive: the src/bridge.c populate() shape — a keyword is the last
 * token on the line, so the follow-up strtok() is NULL -> reported */
int keyword_value(char *buf, char *dst, size_t len)
{
	char *tok;
	int vid = 0;

	for (tok = strtok(buf, " \t"); tok; tok = strtok(NULL, " \t")) {
		// ok: strtok-result-unchecked
		if (!strcmp(tok, "vid")) {
			tok = strtok(NULL, " \t");
			// ruleid: strtok-result-unchecked
			vid = strtol(tok, NULL, 10);
			continue;
		}
		tok = strtok(NULL, " \t");
		// ruleid: strtok-result-unchecked
		strlcpy(dst, tok, len);
	}
	return vid;
}

/* negative: guarded with if (!tok) return -> not reported */
int guarded_return(char *buf)
{
	char *tok = strtok(buf, " ");

	if (!tok)
		return -1;
	// ok: strtok-result-unchecked
	return strtol(tok, NULL, 10);
}

/* negative: guarded with == NULL and continue in a loop -> not reported */
int guarded_continue(char *lines[], int n)
{
	int sum = 0;

	for (int i = 0; i < n; i++) {
		char *tok = strtok(lines[i], " ");

		if (tok == NULL)
			continue;
		// ok: strtok-result-unchecked
		sum += strlen(tok);
	}
	return sum;
}

/* negative: use only inside if (tok) -> not reported */
size_t inside_if(char *buf)
{
	char *tok = strtok(buf, ",");

	if (tok) {
		// ok: strtok-result-unchecked
		return strlen(tok);
	}
	return 0;
}

/* boundary: compared before the guard, then guarded -> first reported */
int compare_then_guard(char *buf)
{
	char *tok = strtok(buf, " ");

	// ruleid: strtok-result-unchecked
	if (!strcmp(tok, "show"))
		return 1;
	if (!tok)
		return -1;
	// ok: strtok-result-unchecked
	return strcmp(tok, "help") == 0;
}

/* corner: strtok() result passed to a function we do not model -> not reported */
void consume(const char *s);
void unmodelled_sink(char *buf)
{
	// ok: strtok-result-unchecked
	consume(strtok(buf, " "));
}
