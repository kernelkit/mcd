# nix/microvms/mkVm.nix
#
# The NixOS guest that runs mcd's network test suite (test/*.sh) as root on
# a real kernel. Shape follows xtcp2's microVMs:
#
#   - qemu_kvm, -cpu host; SLiRP `user` NIC (no host root, no taps)
#   - the host /nix/store shared over 9p, so the build tree and every tool
#     is the host's store path; nothing is copied into an image
#   - ttyS0 on a TCP chardev for expect, hvc0 (virtconsole) for the
#     journal and kernel log; root autologin on both
#   - bridge / veth / 8021q / dummy modules, plus everything test/lib.sh
#     calls (iproute2, tshark, socat, ethtool, jq, util-linux)
#
# The same guest serves the multicast topology's nodes (vm-topo): those
# drop the SLiRP NIC and get point-to-point `-netdev dgram` links instead,
# one virtio-net NIC per link, renamed by MAC to the name in constants.nix
# (p1, lan0, ...). The links are unix datagram socket pairs, as in xtcp2's
# lacp pair: each end binds its own socket and sends to its peer's, so a
# link is a wire with exactly two ends - no tap, no host bridge, no root.
#
# Returns the microvm.nix runner (bin/microvm-run).

{
  pkgs,
  lib,
  nixpkgs,
  microvm,
  # hostname, serialPort, virtioPort, mem, vcpu
  node,
  # Point-to-point links: [ { name mac local remote } ], see constants.nix.
  links ? [ ],
  # The SLiRP NIC; the topology nodes need no outside network.
  uplink ? true,
  # packages.nix testTools: what test/*.sh needs.
  testTools,
}:

let
  # The SLiRP NIC is enp0s3 or similar; networkd matches it by MAC.
  uplinkMac = "02:00:00:00:37:01";

  # Pinned PCI slots so the NICs enumerate in a fixed order.
  linkArgs = lib.concatLists (
    lib.imap0 (i: l: [
      "-netdev"
      "dgram,id=${l.name},local.type=unix,local.path=${l.local},remote.type=unix,remote.path=${l.remote}"
      "-device"
      "virtio-net-pci,netdev=${l.name},mac=${l.mac},addr=0x${lib.toHexString (16 + i)},romfile="
    ]) links
  );

  # make-check.exp's valgrind mode moves the tree's src/mcd to src/mcd.real
  # and symlinks this in its place: every mcd the tests start then runs
  # under valgrind, one log per process in /tmp/vg. Errors do not change
  # mcd's exit status; the driver counts them from the logs.
  mcdValgrind = pkgs.writeShellApplication {
    name = "mcd-valgrind";
    runtimeInputs = [ pkgs.valgrind ];
    text = ''
      exec valgrind -q --log-file=/tmp/vg/mcd.%p --leak-check=full \
        --error-exitcode=0 "$0.real" "$@"
    '';
  };
in
(nixpkgs.lib.nixosSystem {
  inherit pkgs;
  modules = [
    microvm.nixosModules.microvm
    (
      { config, ... }:
      {
        system.stateVersion = "26.05";
        networking.hostName = node.hostname;

        # Trim the guest.
        documentation.enable = false;
        security.polkit.enable = false;
        services.udisks2.enable = false;
        programs.command-not-found.enable = false;
        fonts.fontconfig.enable = false;
        nix.enable = false;
        xdg.mime.enable = false;
        hardware.enableRedistributableFirmware = false;
        boot.supportedFilesystems = lib.mkForce [ "ext4" ];

        # The tests bring up their own interfaces; nothing else should
        # touch them (or send IGMP/MLD on them).
        networking.firewall.enable = false;
        networking.useDHCP = false;
        systemd.network.enable = true;
        # networkd takes the first .network file that matches, in lexical
        # order: the uplink, then everything else unmanaged.
        systemd.network.networks."05-uplink" = lib.mkIf uplink {
          matchConfig.MACAddress = uplinkMac;
          networkConfig.DHCP = "yes";
        };
        systemd.network.networks."99-unmanaged" = {
          matchConfig.Name = "*";
          linkConfig.Unmanaged = true;
        };
        systemd.network.links = lib.listToAttrs (
          map (l: {
            name = "10-${l.name}";
            value = {
              matchConfig.MACAddress = l.mac;
              linkConfig.Name = l.name;
            };
          }) links
        );

        microvm = {
          hypervisor = "qemu";
          inherit (node) mem vcpu;
          cpu = null; # -enable-kvm -cpu host
          interfaces = lib.optional uplink {
            type = "user";
            id = "eth0";
            mac = uplinkMac;
          };
          shares = [
            {
              source = "/nix/store";
              mountPoint = "/nix/.ro-store";
              tag = "ro-store";
              proto = "9p";
            }
          ];
          qemu = {
            serialConsole = false;
            package = pkgs.qemu_kvm;
            extraArgs = [
              "-name"
              "${node.hostname},process=${node.hostname}"
              "-serial"
              "tcp:127.0.0.1:${toString node.serialPort},server,nowait"
              "-device"
              "virtio-serial-pci"
              "-chardev"
              "socket,id=virtcon,port=${toString node.virtioPort},host=127.0.0.1,server=on,wait=off"
              "-device"
              "virtconsole,chardev=virtcon"
            ]
            ++ linkArgs
            ++ [
              "-append"
              (lib.concatStringsSep " " (
                [
                  "console=ttyS0,115200"
                  "console=hvc0"
                  "reboot=t"
                  "panic=-1"
                  "loglevel=4"
                  "init=${config.system.build.toplevel}/init"
                ]
                ++ config.boot.kernelParams
              ))
            ];
          };
        };

        boot.kernelPackages = pkgs.linuxPackages_latest;
        boot.kernelParams = [
          "console=ttyS0,115200"
          "console=hvc0"
          "systemd.show_status=false"
        ];
        boot.initrd.availableKernelModules = [
          "9p"
          "9pnet"
          "9pnet_virtio"
          "virtio_pci"
          "virtio_console"
        ];
        boot.kernelModules = [
          "bridge"
          "veth"
          "8021q"
          "dummy"
        ];

        services.getty.autologinUser = "root";
        systemd.enableEmergencyMode = false;

        # What test/*.sh calls (packages.nix testTools), plus valgrind
        # for make-check.exp's valgrind mode and the coreutils-adjacent
        # tools the drivers use.
        environment.systemPackages = testTools ++ [
          pkgs.valgrind
          mcdValgrind
          pkgs.procps
          pkgs.gnugrep
          pkgs.gnused
          pkgs.gawk
        ];
      }
    )
  ];
}).config.microvm.declaredRunner
