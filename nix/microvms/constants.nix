# nix/microvms/constants.nix
#
# Runtime constants for the mcd microVMs. x86_64 + KVM only: the suite is
# about kernel bridge/multicast behaviour, not the CPU, and the cross
# builds are covered by nix/cross.nix.
{
  hostname = "mcd-vm";

  # Serial console (ttyS0, driven by expect) and virtio console (hvc0,
  # journal + kernel log, tailed into the transcript). Clear of xtcp2
  # (12055) and rocm-ernic (23600).
  serialPort = 23700;
  virtioPort = 23701;

  # Avoid exactly 2048: microvm.nix #171, QEMU hangs at boot.
  mem = 1024;
  vcpu = 4;

  # Seconds. The suite takes a few minutes on KVM; valgrind slows mcd and
  # the suite's own sleeps dominate either way.
  bootTimeout = 300;
  suiteTimeout = 1800;

  # The multicast topology (vm-topo): a switch VM bridging two host VMs,
  # each joined to it by a point-to-point dgram link.
  #
  #   h1 lan0 ──link1── p1 ┐
  #                        sw: br0 10.0.0.10, mcd
  #   h2 lan0 ──link2── p2 ┘
  #
  # h1 (10.0.0.11) is the listener; h2 (10.0.0.2) runs a rival mcd whose
  # lower address wins the querier election. Console ports 23700 + 10·n.
  # `links` name each NIC inside the guest, its MAC, and the unix socket
  # pair (relative: every qemu starts in the runner's one temp directory).
  topo = {
    mem = 768;
    vcpu = 2;
    # Boot of three VMs at once, then the scenario's own waits (election,
    # other-querier-present, leave) - about two minutes on an idle host.
    bootTimeout = 300;
    scenarioTimeout = 600;
    nodes = {
      sw = {
        hostname = "mcd-sw";
        serialPort = 23710;
        virtioPort = 23711;
        links = [
          {
            name = "p1";
            mac = "02:00:00:00:10:01";
            local = "link1-sw.sock";
            remote = "link1-h1.sock";
          }
          {
            name = "p2";
            mac = "02:00:00:00:10:02";
            local = "link2-sw.sock";
            remote = "link2-h2.sock";
          }
        ];
      };
      h1 = {
        hostname = "mcd-h1";
        serialPort = 23720;
        virtioPort = 23721;
        links = [
          {
            name = "lan0";
            mac = "02:00:00:00:20:01";
            local = "link1-h1.sock";
            remote = "link1-sw.sock";
          }
        ];
      };
      h2 = {
        hostname = "mcd-h2";
        serialPort = 23730;
        virtioPort = 23731;
        links = [
          {
            name = "lan0";
            mac = "02:00:00:00:30:01";
            local = "link2-h2.sock";
            remote = "link2-sw.sock";
          }
        ];
      };
    };
  };
}
