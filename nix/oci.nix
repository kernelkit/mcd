# nix/oci.nix
#
# Reproducible OCI (Docker) image for mcd built straight from its Nix
# closure — no Dockerfile. `dockerTools.streamLayeredImage` produces a script
# that streams content-addressed layers to `docker load`, so nothing large is
# materialized in the store and layers dedupe across rebuilds.
#
# Two variants (the `variant` arg):
#   "minimal"  mcd + mctl + the tools mcd shells out to (iproute2, jq).
#              No shell; use `docker exec <c> mctl show`.
#   "debug"    minimal + bash + coreutils. Tagged `<version>-debug`.
#
# A callPackage function: the image architecture follows the package set
# it is called from, native pkgs for amd64 or a nix/cross.nix pkgsCross set
# with that set's cross-built mcd.
#
# Runtime requirements an image cannot express: mcd opens AF_PACKET sockets
# (NET_RAW), uses netlink and multicast membership (NET_ADMIN), and must see
# the bridge it serves, so run with
#   docker run --network host --cap-add NET_ADMIN --cap-add NET_RAW mcd:<tag>
#
# Usage (from flake.nix):
#   oci       = pkgs.callPackage ./nix/oci.nix { inherit mcd; };
#   oci-debug = pkgs.callPackage ./nix/oci.nix { inherit mcd; variant = "debug"; };

{
  lib,
  dockerTools,
  iproute2,
  db,
  libmnl,
  jq,
  bashInteractive,
  coreutils,
  mcd,
  variant ? "minimal",
  # Appended to the tag so cross images don't overwrite the native one in
  # the local image store: mcd:3.0-aarch64, mcd:3.0-aarch64-debug.
  archSuffix ? "",
  tag ? null,
}:

let
  isDebug = variant == "debug";
  inherit (mcd) version;
  imageTag =
    if tag != null then tag else "${version}${archSuffix}${lib.optionalString isDebug "-debug"}";

  # mcd only runs `ip` and `bridge`. Dropping iptables (tc xt), libbpf/elfutils
  # (BPF loading) and python3 (routel) removes curl/openssl/krb5 from the
  # closure and avoids iptables -> libpcap -> rdma-core, which does not
  # cross-build for armv7l.
  iproute2Lean = iproute2.overrideAttrs (_: {
    buildInputs = [
      db
      libmnl
    ];
  });

  contents = [
    mcd
    iproute2Lean
    jq
    dockerTools.fakeNss
  ]
  ++ lib.optionals isDebug [
    bashInteractive
    coreutils
  ];
in
dockerTools.streamLayeredImage {
  name = "mcd";
  tag = imageTag;
  inherit contents;

  # Writable runtime dirs (pid file + IPC socket in /run, /tmp for popen'd
  # tools) and the sample config at the path baked into the binary. Paths are
  # relative to the image root.
  extraCommands = ''
    mkdir -p tmp run etc
    chmod 1777 tmp
    cp ${mcd.src}/mcd.conf etc/mcd.conf
  '';

  config = {
    # Foreground, logging to stderr; extra args (e.g. `-l debug`) append.
    Entrypoint = [
      "${mcd}/bin/mcd"
      "-n"
    ];
    Env = [ "PATH=/bin" ];
    WorkingDir = "/";
    Labels = {
      "org.opencontainers.image.title" = "mcd";
      "org.opencontainers.image.description" = "IGMP/MLD querier for Linux bridges";
      "org.opencontainers.image.source" = "https://github.com/kernelkit/mcd";
      "org.opencontainers.image.licenses" = "ISC";
      "org.opencontainers.image.version" = version;
      "org.opencontainers.image.variant" = variant;
    };
  };
}
