# nix/package.nix
#
# Autotools build of mcd (the querier daemon) and mctl (its client), as a
# callPackage-style package: nixpkgs supplies stdenv and the build tools,
# and every variant is an .override of the one recipe (ctx.mcd):
#
#   ctx.mcd                                            gcc, as CI
#   ctx.mcd.override { stdenv = pkgs.clangStdenv; }    clang
#   ctx.mcd.override { werror = true; }
#   ctx.mcd.override { sanitizers = [ "address" "undefined" ]; }
#   ctx.mcd.override { enableTest = true; installBuildTree = true; }
#   pkgs.pkgsCross.<target>.callPackage ./package.nix { inherit ctx; }
#
# autoreconfHook stands in for ./autogen.sh; the generic configure / make /
# make install phases do the rest. Taking autoreconfHook and bison as
# arguments lets nixpkgs pick build-machine copies when cross-compiling.
#
# The network test suite is not run here (doCheck = false): it needs network
# namespaces, bridges and raw sockets, which the build sandbox lacks. It runs
# in the microVM instead (nix/microvms/), against an `installBuildTree` build.

{
  lib,
  stdenv,
  autoreconfHook,
  bison,
  # The flake's shared context (nix/context.nix): sources, version and
  # configure flags, all system-independent.
  ctx,
  pnameSuffix ? "",
  werror ? false,
  # -fsanitize= values, e.g. [ "address" "undefined" ] or [ "thread" ].
  sanitizers ? [ ],
  # -fno-sanitize= values, e.g. [ "alignment" ].
  noSanitize ? [ ],
  # --enable-test: adds test/ to SUBDIRS so `make check` runs the suite.
  enableTest ? false,
  # Install the configured + built tree under $out/share/mcd/build, so the
  # microVM can run `make check` against exactly these binaries. (Not
  # keepBuildTree: callPackage would fill that from nixpkgs' setup hook.)
  installBuildTree ? false,
  extraConfigureFlags ? [ ],
}:

let
  inherit (ctx) version;

  sanFlags = lib.optionalString (sanitizers != [ ]) (
    "-fsanitize=${lib.concatStringsSep "," sanitizers} -fno-omit-frame-pointer -g"
    + lib.optionalString (noSanitize != [ ]) " -fno-sanitize=${lib.concatStringsSep "," noSanitize}"
  );
in
stdenv.mkDerivation {
  pname = "mcd${pnameSuffix}";
  inherit version;
  # Test scripts only reach the --enable-test trees, so editing one does
  # not rebuild the package.
  src = if enableTest then ctx.srcTest else ctx.srcBuild;

  nativeBuildInputs = [
    autoreconfHook
    bison
  ];

  configureFlags =
    ctx.configureFlags ++ lib.optional enableTest "--enable-test" ++ extraConfigureFlags;

  env = {
    NIX_CFLAGS_COMPILE = lib.concatStringsSep " " (
      lib.optional werror "-Werror" ++ lib.optional (sanFlags != "") sanFlags
    );
  }
  // lib.optionalAttrs (sanFlags != "") {
    NIX_CFLAGS_LINK = sanFlags;
  };

  # _FORTIFY_SOURCE interposes on the libc calls the sanitizers intercept,
  # hiding bugs from ASan and confusing TSan.
  hardeningDisable = lib.optional (sanitizers != [ ]) "fortify";

  enableParallelBuilding = true;

  doCheck = false;

  # A kept tree is for running under sanitizers / valgrind in the microVM:
  # keep its symbols so the reports are readable.
  dontStrip = installBuildTree;

  postInstall = lib.optionalString installBuildTree ''
    mkdir -p "$out/share/mcd"
    cp -a . "$out/share/mcd/build"
  '';

  # Same smoke test as CI: both binaries start and print usage.
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    # `mcd -h` exits without freeing its startup allocations; that is not
    # what a sanitizer build is for.
    export ASAN_OPTIONS=detect_leaks=0
    "$out/bin/mcd" -h >/dev/null
    "$out/bin/mctl" -h >/dev/null
    runHook postInstallCheck
  '';

  meta = {
    description = "IGMP/MLD querier for Linux bridges";
    homepage = "https://github.com/kernelkit/mcd";
    license = lib.licenses.isc;
    platforms = lib.platforms.linux;
    mainProgram = "mcd";
  };
}
