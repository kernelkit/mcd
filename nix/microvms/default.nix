# nix/microvms/default.nix
#
# MicroVM integration tests: mcd's network test suite (test/*.sh, via
# `make check`) run as root on a real kernel in a KVM guest, driven over
# the serial console with expect (nix/microvms/console/).
#
# Outputs (x86_64-linux only; KVM needs no other host privilege):
#   packages.microvm             the microvm.nix runner (bin/microvm-run)
#   packages/apps.vm-check       the suite against the plain build
#   packages/apps.vm-check-asan  the suite against an ASan + UBSan build,
#                                sanitizer reports counted and printed
#   packages/apps.vm-check-valgrind  the suite with mcd under valgrind
#   packages/apps.vm-topo        three VMs (switch + two hosts) on dgram
#                                links: election, snooping, leave, takeover
#   checks.vm-lib-exp            the expect library + drivers, hermetic
#
# One VM serves all three make-check runners, and each driver picks its
# build tree by store path: the guest sees the host's whole store over 9p,
# so neither the trees nor the topology's mcd are in a guest closure, and
# a source edit rebuilds no guest. vm-topo has its own three.

{
  ctx,
  nixpkgs,
  microvm,
}:

let
  inherit (ctx) pkgs lib;
  constants = import ./constants.nix;

  inherit (ctx) mcd;

  # Configured --enable-test build trees, installed under share/mcd/build.
  testTree = mcd.override {
    pnameSuffix = "-test-tree";
    enableTest = true;
    installBuildTree = true;
  };
  asanTree = mcd.override {
    pnameSuffix = "-asan-test-tree";
    enableTest = true;
    installBuildTree = true;
    sanitizers = [
      "address"
      "undefined"
    ];
  };
  treePath = t: "${t}/share/mcd/build";

  console = import ./console {
    inherit pkgs lib;
    drivers = {
      "make-check.exp" = ./scripts/make-check.exp;
      "multicast-topo.exp" = ./scripts/multicast-topo.exp;
    };
  };

  mkVm =
    args:
    import ./mkVm.nix (
      {
        inherit
          pkgs
          lib
          nixpkgs
          microvm
          ;
        inherit (ctx.packages) testTools;
      }
      // args
    );

  vm = mkVm {
    node = {
      inherit (constants)
        hostname
        serialPort
        virtioPort
        mem
        vcpu
        ;
    };
  };

  # The multicast topology: three VMs, each running mcd from the store.
  topo = constants.topo;
  topoVms = lib.mapAttrs (
    _: n:
    mkVm {
      node = n // {
        inherit (topo) mem vcpu;
      };
      inherit (n) links;
      uplink = false;
    }
  ) topo.nodes;

  inherit
    (import ./runners.nix {
      inherit pkgs lib constants;
      inherit (console) scripts;
    })
    mkRunner
    mkCheckRunner
    ;

  mkSuite =
    name: tree: mode: description:
    mkCheckRunner {
      inherit name vm description;
      driver = "make-check.exp";
      driverArgs = [
        (toString constants.bootTimeout)
        (toString constants.suiteTimeout)
        (treePath tree)
        mode
      ];
    };

  # sw first: h1 and h2 send to its sockets, and a datagram to a socket
  # that is not bound yet is dropped, which the scenario's own waits cover.
  vm-topo = mkRunner {
    name = "vm-topo";
    description = "multicast topology: querier election, snooping, leave, takeover";
    vms =
      map
        (n: {
          name = n;
          vm = topoVms.${n};
          inherit (topo.nodes.${n}) serialPort virtioPort;
        })
        [
          "sw"
          "h1"
          "h2"
        ];
    driver = "multicast-topo.exp";
    driverArgs = map toString [
      topo.nodes.sw.serialPort
      topo.nodes.h1.serialPort
      topo.nodes.h2.serialPort
      "${mcd}/bin"
      topo.bootTimeout
    ];
    summary = "MCD_TOPO";
    timeout = topo.bootTimeout + topo.scenarioTimeout;
  };

  # The host-side runners, each a package and an app of the same name.
  runners = {
    vm-check = mkSuite "vm-check" testTree "plain" "make check in the microVM";
    vm-check-asan =
      mkSuite "vm-check-asan" asanTree "asan"
        "make check in the microVM against an ASan + UBSan build";
    vm-check-valgrind =
      mkSuite "vm-check-valgrind" testTree "valgrind"
        "make check in the microVM with mcd under valgrind";
    inherit vm-topo;
  };

  app = drv: {
    type = "app";
    program = lib.getExe drv;
  };
in
{
  packages = runners // {
    microvm = vm;
    microvm-topo-sw = topoVms.sw;
    microvm-topo-h1 = topoVms.h1;
    microvm-topo-h2 = topoVms.h2;
    mcd-test-tree = testTree;
    mcd-asan-test-tree = asanTree;
  };
  apps = lib.mapAttrs (_: app) runners;
  checks.vm-lib-exp = console.check;
}
