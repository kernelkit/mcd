EXTRA_DIST         = lib.sh basic.sh sleepy.sh two.sh ipc.sh ipc-errors.sh ipc-disconnect.sh late.sh router-ports.sh static-group.sh mld.sh
CLEANFILES         = *~ *.trs *.log

TEST_EXTENSIONS    = .sh
TESTS_ENVIRONMENT  = unshare -mrun --map-auto

TESTS              = sleepy.sh
TESTS             += basic.sh
TESTS             += ipc.sh
TESTS             += ipc-errors.sh
TESTS             += ipc-disconnect.sh
TESTS             += late.sh
TESTS             += two.sh
TESTS             += router-ports.sh
TESTS             += static-group.sh
TESTS             += mld.sh
