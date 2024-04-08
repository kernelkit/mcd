/* SPDX-License-Identifier: ISC */

#include "defs.h"
#include <err.h>
#include <getopt.h>
#include <paths.h>
#include <fcntl.h>
#include <poll.h>

int haveterminal = 1;
int running = 1;
int use_syslog = 1;
time_t mcd_init_time;

char *config_file = NULL;
char *pid_file    = NULL;
char *sock_file   = NULL;

char *ident       = PACKAGE_NAME;
char *prognm      = NULL;
const char *versionstring = "mcd version " PACKAGE_VERSION;

/*
 * Forward declarations.
 */
static void handle_signals(int, void *);

static int compose_paths(void)
{
    /* Default .conf file path: "/etc" + '/' + "mcd" + ".conf" */
    if (!config_file) {
	size_t len = strlen(SYSCONFDIR) + strlen(ident) + 7;

	config_file = malloc(len);
	if (!config_file) {
	    logit(LOG_ERR, errno, "Failed allocating memory, exiting.");
	    exit(1);
	}

	snprintf(config_file, len, _PATH_MCD_CONF, ident);
    }

    /* Default is to let pidfile() API construct PID file from ident */
    if (!pid_file)
	pid_file = strdup(ident);

    return 0;
}

static int usage(int code)
{
    char pidbuf[strlen(pid_file) + 10];
    char ipcbuf[strlen(_PATH_MCD_SOCK) + 42];
    char *nm = PACKAGE_NAME;
    char *sockfn = ipcbuf;
    char *pidfn = pidbuf;

    if (pid_file[0] == '/')
	pidfn = pid_file;
    else
	snprintf(pidbuf, sizeof(pidbuf), "/run/%s.pid", pid_file);

    if (sock_file)
	sockfn = sock_file;
    else
	snprintf(ipcbuf, sizeof(ipcbuf), _PATH_MCD_SOCK, ident);

    printf("Usage: %s [-himnpsv] [-f FILE] [-i NAME] [-l LEVEL] [-p FILE] [-u FILE]\n"
	   "\n"
	   "  -f, --config=FILE        Default filename derived from -i: %s\n"
	   "  -h, --help               Show this help text\n"
	   "  -i, --ident=NAME         Identity for syslog, .cfg & .pid file, default: %s\n"
	   "  -l, --loglevel=LEVEL     Set log level: none, err, notice (default), info, debug\n"
	   "  -n, --foreground         Run in foreground, do not detach from controlling terminal\n"
	   "  -p, --pidfile=FILE       Default pidfile, derived from -i: %s\n"
	   "  -s, --syslog             Log to syslog, default unless running in --foreground\n"
	   "  -u, --ipc=FILE           UNIX domain socket, default from -i: %s\n"
	   "  -v, --version            Show program version\n", prognm, config_file, nm, pidfn, sockfn);

    printf("\nBug report address: %-40s\n", PACKAGE_BUGREPORT);

    return code;
}

static char *progname(char *arg0)
{
       char *nm;

       nm = strrchr(arg0, '/');
       if (nm)
	       nm++;
       else
	       nm = arg0;

       return nm;
}

int main(int argc, char *argv[])
{
    struct option long_options[] = {
	{ "config",        1, 0, 'f' },
	{ "help",          0, 0, 'h' },
	{ "ident",         1, 0, 'i' },
	{ "loglevel",      1, 0, 'l' },
	{ "foreground",    0, 0, 'n' },
	{ "pidfile",       1, 0, 'p' },
	{ "syslog",        0, 0, 's' },
	{ "ipc",           1, 0, 'u' },
	{ "version",       0, 0, 'v' },
	{ NULL, 0, 0, 0 }
    };
    int foreground = 0;
    int ch;

    prognm = ident = progname(argv[0]);
    while ((ch = getopt_long(argc, argv, "f:hi:l:np:su:v", long_options, NULL)) != EOF) {
	switch (ch) {
	case 'f':
	    config_file = strdup(optarg);
	    break;

	case 'h':
	    compose_paths();
	    return usage(0);

	case 'i':	/* --ident=NAME */
	    ident = optarg;
	    break;

	case 'l':
	    if (!strcmp(optarg, "?")) {
		char buf[128];

		log_list(buf, sizeof(buf));
		return !puts(buf);
	    }

	    loglevel = log_str2lvl(optarg);
	    if (-1 == loglevel)
		return usage(1);
	    break;

	case 'n':
	    foreground = 1;
	    use_syslog--;
	    break;

	case 'p':	/* --pidfile=NAME */
	    pid_file = strdup(optarg);
	    break;

	case 's':	/* --syslog */
	    use_syslog++;
	    break;

	case 'u':
	    sock_file = strdup(optarg);
	    break;

	case 'v':
	    printf("%s\n", versionstring);
	    return 0;

	default:
	    return usage(1);
	}
    }

    if (geteuid() != 0) {
	fprintf(stderr, "%s: must be root\n", ident);
	exit(1);
    }

    if (!foreground) {
#ifdef TIOCNOTTY
	int fd;
#endif

	/* Detach from the terminal */
	haveterminal = 0;
	if (fork())
	    exit(0);

	(void)close(0);
	(void)close(1);
	(void)close(2);
	(void)open("/dev/null", O_RDONLY);
	(void)dup2(0, 1);
	(void)dup2(0, 2);
#ifdef TIOCNOTTY
	fd = open("/dev/tty", O_RDWR);
	if (fd >= 0) {
	    (void)ioctl(fd, TIOCNOTTY, NULL);
	    (void)close(fd);
	}
#else
	if (setsid() < 0)
	    perror("setsid");
#endif
    } else
	setlinebuf(stderr);

    /*
     * Setup logging
     */
    log_init(ident);
    logit(LOG_DEBUG, 0, "%s starting", versionstring);

    compose_paths();

    pev_init();
    igmp_init();
    config_init();
    netlink_init();
    iface_init();

    pev_sig_add(SIGHUP,  handle_signals, NULL);
    pev_sig_add(SIGINT,  handle_signals, NULL);
    pev_sig_add(SIGTERM, handle_signals, NULL);
    pev_sig_add(SIGUSR1, handle_signals, NULL);
    pev_sig_add(SIGUSR2, handle_signals, NULL);

    /* Open channel to for client(s) */
    ipc_init(sock_file);

    /* Signal world we are now ready to start taking calls */
    if (pidfile(pid_file))
	logit(LOG_WARNING, errno, "Cannot create pidfile");

    return pev_run();
}

static void cleanup(void)
{
    static int in_cleanup = 0;

    if (!in_cleanup) {
	in_cleanup++;

	iface_exit();
	igmp_exit();
	netlink_exit();
	ipc_exit();
    }
}

/*
 * Signal handler.  Take note of the fact that the signal arrived
 * so that the main loop can take care of it.
 */
static void handle_signals(int signo, void *arg)
{
    switch (signo) {
	case SIGINT:
	case SIGTERM:
	    logit(LOG_NOTICE, 0, "%s exiting", versionstring);
	    cleanup();
	    free(pid_file);
	    free(config_file);
	    pev_exit(0);
	    break;

	case SIGHUP:
	    restart();
	    break;

	case SIGUSR1:
	case SIGUSR2:
	    /* ignored for now */
	    break;
    }
}

void restart(void)
{
    /*
     * reset all the entries
     */
    iface_exit();
    igmp_exit();
    netlink_exit();
    ipc_exit();

    igmp_init();
    config_init();
    netlink_init();
    iface_init();
    ipc_init(sock_file);

    /* Touch PID file to acknowledge SIGHUP */
    pidfile(pid_file);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
