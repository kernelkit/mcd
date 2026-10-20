EXTRA_DIST         = lib.sh config-check.sh completion.sh topology.sh basic.sh sleepy.sh two.sh ipc.sh ipc-errors.sh ipc-disconnect.sh router-timeout.sh late.sh router-ports.sh static-group.sh mld.sh bridge-names.sh mctl-help.sh
CLEANFILES         = *~ *.trs *.log

TEST_EXTENSIONS    = .sh
TESTS_ENVIRONMENT  = unshare -mrun --map-auto

TESTS              = config-check.sh
TESTS             += sleepy.sh
TESTS             += basic.sh
TESTS             += ipc.sh
TESTS             += ipc-errors.sh
TESTS             += ipc-disconnect.sh
TESTS             += router-timeout.sh
TESTS             += late.sh
TESTS             += two.sh
TESTS             += router-ports.sh
TESTS             += static-group.sh
TESTS             += mld.sh
TESTS             += bridge-names.sh
TESTS             += mctl-help.sh
TESTS             += completion.sh
TESTS             += topology.sh
