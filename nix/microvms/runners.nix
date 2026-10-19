# nix/microvms/runners.nix
#
# Host-side runners for the mcd microVMs. mkRunner wraps one expect driver
# and any number of VMs in a writeShellApplication: runner.sh, given the
# runner's JSON config (VMs, driver, arguments, timeout). It:
#
#   1. checks /dev/kvm and that every console port is free
#   2. boots every VM in the background (microvm-run), all from ONE fresh
#      directory: the topology's dgram links are relative unix socket
#      paths, so the qemus find each other there, and a fresh directory
#      means no stale socket from a killed run can fail a bind
#   3. tails each virtio console (journal, kernel log) into the logs; the
#      serial consoles take one client each and the driver owns them
#   4. runs the driver under an overall timeout
#   5. if the driver died before printing its summary line, runs
#      node-diag.exp on each VM for dmesg / links / the journal
#   6. tears every VM down in an EXIT trap (unless --keep)
#
# mkCheckRunner is the one-VM case, for make-check.exp.
#
# Exit codes: 0 pass, 1 test failure, 2 no console, 3 setup (no KVM, port
# busy, a driver setup step failed), 124 overall timeout.

{
  pkgs,
  lib,
  constants,
  scripts,
}:

let
  mkRunner =
    {
      name,
      description,
      # [ { name vm serialPort virtioPort } ]
      vms,
      # Driver script in `scripts` and its arguments (ports included).
      driver,
      driverArgs,
      # The prefix of the driver's summary line, e.g. "MCD_CHECK".
      summary,
      timeout,
    }:
    let
      config = pkgs.writeText "${name}-config.json" (
        builtins.toJSON {
          inherit
            name
            description
            summary
            timeout
            driverArgs
            ;
          vms = map (v: {
            inherit (v) name serialPort virtioPort;
            run = "${v.vm}/bin/microvm-run";
          }) vms;
          driver = "${scripts}/${driver}";
          nodeDiag = "${scripts}/node-diag.exp";
          diagCmds = [
            "uname -a"
            "dmesg | tail -n 40"
            "ip -d -br link"
            "bridge -d link"
            "journalctl -b --no-pager -p warning | tail -n 40"
          ];
        }
      );
    in
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = with pkgs; [
        coreutils
        expect
        netcat-gnu
        gnugrep
        jq
      ];
      text = ''
        config=${config}
      ''
      + builtins.readFile ./runner.sh;
    };
in
{
  inherit mkRunner;

  mkCheckRunner =
    {
      name,
      vm,
      description,
      driver,
      driverArgs,
    }:
    mkRunner {
      inherit name description driver;
      vms = [
        {
          inherit (constants) serialPort virtioPort;
          name = constants.hostname;
          inherit vm;
        }
      ];
      driverArgs = [ (toString constants.serialPort) ] ++ driverArgs;
      summary = "MCD_CHECK";
      timeout = constants.bootTimeout + constants.suiteTimeout + 120;
    };
}
