# nix/context.nix
#
# Shared build context for the mcd flake. It is built once in flake.nix and
# threaded (as `ctx`) into every module, so none of them re-imports
# packages.nix, re-hardcodes the version or rebuilds mcd's recipe.
#
# Fields:
#   pkgs, lib       the flake's per-system inputs, passed through
#   srcBuild        the source configure + make read (no test scripts)
#   srcTest         srcBuild + test/, for the --enable-test trees
#   srcAnalysis     srcBuild without the docs, for the analysis builds
#   srcCode         src/ + lib/ only, for the source scanners
#   srcConf         the sample mcd.conf alone
#   mcd             the package (package.nix); variants are mcd.override
#   packages        dependency / tool sets (nix/packages.nix)
#   version         read from AC_INIT in configure.ac — the single source
#   runtimeDirs     the runtime dirs baked into mcd (/etc, /var, /run)
#   runtimePaths    runtimeDirs as configure flags
#   configureFlags  runtimePaths + sbindir=$out/bin, for the package build
#   configureVpath  shell snippet: autoreconf + out-of-tree configure (analysis)
#   scrubStore      sed program stripping /nix/store/<hash>-<name>/
#   sanitizerFlags  ASan + UBSan, aborting on the first finding
#   inTreeDiagnostics  installPhase snippet: build check + in-tree report.txt
#   mkAnalysisDrv   base derivation for the analysis builds
#
# Usage:
#   ctx = import ./nix/context.nix { inherit pkgs lib; };

{ pkgs, lib }:

let
  packages = import ./packages.nix { inherit pkgs; };

  # AC_INIT([mcd], [3.0], [...]) -> "3.0"
  version =
    let
      matches = lib.filter (m: m != null) (
        map (builtins.match "AC_INIT[(][[]mcd[]], *[[]([0-9A-Za-z.~-]+)[]].*") (
          lib.splitString "\n" (builtins.readFile ../configure.ac)
        )
      );
    in
    if matches == [ ] then
      throw "context.nix: cannot parse AC_INIT version from configure.ac"
    else
      lib.head (lib.head matches);

  # Sources, as small as each consumer allows, so an edit only rebuilds
  # what reads it. None includes nix/ or the flake.
  #   srcBuild  what configure + make read: the autotools files, src/,
  #             lib/, man/, the installed docs (doc_DATA, EXTRA_DIST) and,
  #             from test/, only the Makefile.am configure needs
  #   srcTest   srcBuild + test/, for the --enable-test trees
  #   srcAnalysis  configure + make -C src, for the analysis and fuzz
  #             builds: srcBuild without the docs (automake is `foreign`)
  #   srcCode   src/ + lib/, for the tools that only scan C source
  fs = lib.fileset;
  srcAnalysisFiles = fs.unions [
    ../configure.ac
    ../Makefile.am
    ../src
    ../lib
    ../man
    ../test/Makefile.am
  ];
  srcAnalysis = fs.toSource {
    root = ../.;
    fileset = srcAnalysisFiles;
  };
  srcBuildFiles = fs.unions [
    srcAnalysisFiles
    ../README.md
    ../ChangeLog.md
    ../LICENSE
    ../mcd.conf
    (fs.fileFilter (f: f.hasExt "svg") ../doc)
  ];
  srcBuild = fs.toSource {
    root = ../.;
    fileset = srcBuildFiles;
  };
  srcTest = fs.toSource {
    root = ../.;
    fileset = fs.union srcBuildFiles ../test;
  };
  # The sample mcd.conf alone (the fuzz config corpus seeds from it).
  srcConf = fs.toSource {
    root = ../.;
    fileset = ../mcd.conf;
  };
  srcCode = fs.toSource {
    root = ../.;
    fileset = fs.unions [
      ../src
      ../lib
    ];
  };

  # Bake the real runtime paths into the binary (SYSCONFDIR, RUNSTATEDIR,
  # PRESERVEDIR in src/Makefile.am) instead of $out/etc, $out/var/run. The
  # sample mcd.conf still installs under $out/share/doc. sbindir=$out/bin so
  # `nix run` and lib.getExe find mcd. Builds that skip configure (the fuzz
  # harnesses) get the same values as -D flags from runtimeDirs.
  runtimeDirs = {
    sysconfdir = "/etc";
    localstatedir = "/var";
    runstatedir = "/run";
  };
  runtimePaths = lib.mapAttrsToList (n: v: "--${n}=${v}") runtimeDirs;
  configureFlags = runtimePaths ++ [ "--sbindir=${placeholder "out"}/bin" ];

  # The analysis builds configure out of tree, in $srcTop/_build, invoking
  # configure by absolute path. automake then hands the compiler absolute
  # source paths, so every diagnostic reads $srcTop/src/foo.c and strips to
  # the repo-relative src/foo.c. Expects `srcTop` set by the caller; extra
  # configure arguments (already quoted) go in `extra`.
  configureVpath = extra: ''
    (cd "$srcTop" && autoreconf -fi)
    mkdir -p "$srcTop/_build"
    cd "$srcTop/_build"
    "$srcTop/configure" ${lib.escapeShellArgs runtimePaths} ${extra}
  '';

  # Strip /nix/store/<hash>-<name>/ prefixes so paths in a report read as
  # repo-relative.
  scrubStore = ''sed 's|/nix/store/[a-z0-9]\{32\}-[^/]*/||g' '';

  # The sanitizers the unit tests and fuzz harnesses build with: any
  # finding aborts the run.
  sanitizerFlags = "-fsanitize=address,undefined -fno-sanitize-recover=undefined";

  # installPhase snippet shared by the in-tree analysis builds (gcc,
  # clang-analyzer): fail unless the build produced mcd, then write
  # $out/report.txt with the repo-relative src/ and lib/ diagnostics from
  # `log` (cfparse.y lines via bison's #line directives).
  inTreeDiagnostics = name: log: ''
    if [ ! -x "$srcTop/_build/src/mcd" ]; then
      tail -30 "${log}" >&2
      echo "${name}: build failed; report is incomplete" >&2
      exit 1
    fi
    mkdir -p $out
    grep -E ': warning:|: error:' "${log}" \
      | sed "s|$srcTop/||g" \
      | grep -E '^(src|lib)/' > $out/report.txt || true
  '';

  # Base derivation for the analysis builds: srcAnalysis (they `make -C
  # src`, which builds the lib/ replacements too), autotools without the
  # setup hook (configureVpath runs autoreconf itself), and no
  # install/fixup machinery. Callers supply buildPhase / installPhase and may
  # add tools via `extraNativeBuildInputs`; anything they pass wins.
  mkAnalysisDrv =
    {
      name,
      extraNativeBuildInputs ? [ ],
      ...
    }@args:
    pkgs.stdenv.mkDerivation (
      {
        pname = "mcd-analysis-${name}";
        inherit version;
        src = srcAnalysis;
        nativeBuildInputs = [
          pkgs.autoconf
          pkgs.automake
          pkgs.bison
        ]
        ++ extraNativeBuildInputs;
        dontConfigure = true;
        dontFixup = true;
        doCheck = false;
      }
      // removeAttrs args [
        "name"
        "extraNativeBuildInputs"
      ]
    );

  ctx = {
    inherit
      pkgs
      lib
      srcBuild
      srcAnalysis
      srcTest
      srcCode
      srcConf
      packages
      version
      runtimeDirs
      runtimePaths
      configureFlags
      configureVpath
      scrubStore
      sanitizerFlags
      inTreeDiagnostics
      mkAnalysisDrv
      ;
    mcd = pkgs.callPackage ./package.nix { inherit ctx; };
  };
in
ctx
