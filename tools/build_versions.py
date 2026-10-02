#!/usr/bin/env python3
"""Build SniffCraft for several Minecraft versions, for the Wireshark extcap version selector.

Each build is written to <output>/sniffcraft_versions/sniffcraft-<version>[.exe]. Builds are
headless but keep the byte offsets of parsed fields, so Wireshark can highlight them. The
extcap (any SniffCraft build) lists them in its "Minecraft version" option when they are in
a sniffcraft_versions folder next to it.

Usage:
  python tools/build_versions.py                  # all the versions in VERSIONS
  python tools/build_versions.py 1.20.1 1.8.9     # only these versions
  python tools/build_versions.py --list-json      # print VERSIONS as json (CI matrix)
"""

import argparse
import json
import pathlib
import shutil
import subprocess
import sys

# One version per protocol: the last release of each old minor version, every protocol since 1.20
VERSIONS = [
    "1.8.9", "1.9.4", "1.10.2", "1.11.2", "1.12.2", "1.13.2", "1.14.4", "1.15.2", "1.16.5",
    "1.17.1", "1.18.2", "1.19.2", "1.19.4",
    "1.20.1", "1.20.2", "1.20.4", "1.20.6",
    "1.21.1", "1.21.3", "1.21.4", "1.21.5", "1.21.6", "1.21.8", "1.21.10", "1.21.11",
    "26.1.2", "26.2", "26.3",
]

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXE_SUFFIX = ".exe" if sys.platform == "win32" else ""


def find_cmake():
    cmake = shutil.which("cmake")
    if cmake is not None:
        return cmake
    # Visual Studio bundles cmake without adding it to the PATH
    vswhere = pathlib.Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
    if vswhere.exists():
        found = subprocess.run([str(vswhere), "-latest", "-products", "*", "-find", r"Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"],
                               capture_output=True, text=True).stdout.strip().splitlines()
        if found:
            return found[0]
    sys.exit("cmake not found, use --cmake")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("versions", nargs="*", help="Minecraft versions to build (default: all the versions in VERSIONS)")
    parser.add_argument("--list-json", action="store_true", help="print the default versions as json and exit")
    parser.add_argument("--build-dir", default=str(ROOT / "build-versions"), help="cmake build folder, reused between versions")
    parser.add_argument("--output", default=str(ROOT / "dist"), help="the builds go in its sniffcraft_versions folder")
    parser.add_argument("--cmake", help="cmake executable")
    parser.add_argument("--force", action="store_true", help="rebuild versions that are already in the output folder")
    args = parser.parse_args()

    if args.list_json:
        print(json.dumps(VERSIONS))
        return

    cmake = args.cmake or find_cmake()
    build_dir = pathlib.Path(args.build_dir).resolve()
    out_dir = build_dir / "out"
    versions_dir = pathlib.Path(args.output).resolve() / "sniffcraft_versions"
    versions_dir.mkdir(parents=True, exist_ok=True)

    failed = []
    for version in args.versions or VERSIONS:
        target = versions_dir / ("sniffcraft-" + version + EXE_SUFFIX)
        if target.exists() and not args.force:
            print("== %s already built" % version, flush=True)
            continue
        print("== Building SniffCraft for Minecraft %s" % version, flush=True)
        configure = [cmake, "-S", str(ROOT), "-B", str(build_dir),
                     "-DGAME_VERSION=" + version,
                     "-DCMAKE_BUILD_TYPE=Release",
                     "-DSNIFFCRAFT_WITH_GUI=OFF",
                     "-DSNIFFCRAFT_WITH_ENCRYPTION=ON",
                     "-DSNIFFCRAFT_DETAILED_PARSING=ON",
                     # Separate outputs so these builds don't overwrite the main one in bin/ and lib/
                     "-DSNIFFCRAFT_OUTPUT_DIR=" + str(out_dir),
                     "-DBOTCRAFT_OUTPUT_DIR=" + str(out_dir)]
        build = [cmake, "--build", str(build_dir), "--config", "Release", "--parallel", "--target", "sniffcraft"]
        if subprocess.run(configure).returncode != 0 or subprocess.run(build).returncode != 0:
            failed.append(version)
            continue
        shutil.copy2(out_dir / "bin" / ("sniffcraft" + EXE_SUFFIX), target)
        print("== %s -> %s" % (version, target), flush=True)

    if failed:
        sys.exit("Failed versions: " + ", ".join(failed))


if __name__ == "__main__":
    main()
