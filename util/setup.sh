#!/bin/sh
# unshare -mrun ./setup.sh

ip link set lo up
ip link set lo state up

ip link add veth0a type veth peer veth0b
ip link add veth1a type veth peer veth1b
ip link add veth2a type veth peer veth2b
ip link add veth3a type veth peer veth3b
ip link add veth4a type veth peer veth4b
ip link add veth5a type veth peer veth5b

ip link add br0 type bridge
ip link set veth0b master br0
ip link set veth1b master br0

ip link add br1 type bridge
ip link set veth2b master br1
ip link set veth3b master br1

ip link set br0 up
ip link set br1 up

for i in $(seq 0 5); do
    ifacea=veth${i}a
    ifaceb=veth${i}b
    ip link set "$ifacea" up
    ip link set "$ifacea" state up
    ip link set "$ifaceb" up
    ip link set "$ifaceb" state up
done

echo
echo "Virtual network stack up, new shell as PID $$"
echo
echo "$LOGNAME" > /tmp/mcd-setup.user
echo "$$" > /tmp/mcd-setup.pid
exec bash --rcfile .bashrc
