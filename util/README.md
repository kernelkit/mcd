Helper Scripts for Manual Testing
=================================

The following scripts can be used to manually test `mcd` and `mctl` on a
Linux system by leveraging network namespaces.

    cd util/
    ./run -s

Set up environment, see `ip -br link`, the prompt changes to indicate that
you are inside the network namespace.  From here you can start the daemon:

    ./daemon &

The daemon starts up and now you can use `mctl` to inspect the state:

    ./client

Both `daemon` and `client` are helper wrappers.


Starting Another Terminal
-------------------------

A few cases, e.g. running `gdb`, requires more than one terminal window
open in the same network namespace.  The following require an already
running `run -s` instance.

    ./run

This will prompt you for your `sudo` password.  It is required to be
able to access the namespace of the `run -s` process.

