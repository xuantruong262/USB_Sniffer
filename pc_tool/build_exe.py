"""
Pico USB Sniffer - build the stand-alone Windows program (no Python needed to run it).

  build_exe.bat                   both packages below
  build_exe.bat --mode exe        dist/PicoUsbSniffer_<version>.exe   one file, slower to start
  build_exe.bat --mode zip        dist/PicoUsbSniffer_win64_<version>.zip   folder + guide + firmware
  other options: --version 1.2.3  --out FOLDER  --skip-tests  --clean

The build environment lives in %LOCALAPPDATA%/PicoUsbSniffer_build (outside OneDrive,
which locks files while it syncs). Every built exe is started in demo mode and must
write a capture before it is copied to the output folder.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
NAME = "PicoUsbSniffer"
MAIN = os.path.join(HERE, "usb_sniffer_gui.py")
GUIDE = os.path.join(HERE, "HUONG_DAN.txt")
ICON = os.path.join(HERE, "app.ico")
# own build first, else the one delivered with the source package
UF2 = next((p for p in (os.path.join(ROOT, "firmware", d, "usb_sniffer.uf2") for d in ("build", "prebuilt"))
            if os.path.exists(p)), None)
REQ = os.path.join(HERE, "requirements-build.txt")
TESTS = os.path.join(HERE, "tests", "test_pipeline.py")
WORK = os.path.join(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir(), NAME + "_build")
VENV = os.path.join(WORK, "venv")
VPY = os.path.join(VENV, "Scripts", "python.exe")
MIN_PY = (3, 10)
SMOKE_TIMEOUT = 60


class BuildError(Exception):
    pass


def step(text):
    print(f"\n=== {text}", flush=True)


def run(cmd, what, **kw):
    if subprocess.run(cmd, **kw).returncode != 0:
        raise BuildError(f"{what} failed")


def quiet_ok(cmd):
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except OSError:
        return False


def prepare_env(clean):
    step("Build environment")
    if clean and os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK, exist_ok=True)
    # run it: a venv whose base Python was removed / updated still has its python.exe
    if not quiet_ok([VPY, "-c", "import sys"]):
        if os.path.isdir(VENV):
            shutil.rmtree(VENV)
        print("creating", VENV)
        run([sys.executable, "-m", "venv", VENV], "Creating the virtual environment")
    stamp = os.path.join(VENV, "installed.txt")
    want = open(REQ, encoding="utf-8").read()
    have = open(stamp, encoding="utf-8").read() if os.path.exists(stamp) else None
    if have != want or not quiet_ok([VPY, "-c", "import PySide6.QtWidgets, serial, PyInstaller"]):
        print("installing packages (internet needed)...")
        run([VPY, "-m", "pip", "install", "--disable-pip-version-check", "-q", "-r", REQ], "Installing packages")
        with open(stamp, "w", encoding="utf-8") as f:
            f.write(want)
    print("ready:", VENV)


def version_file(version):
    nums = [min(int(x), 65535) for x in re.findall(r"\d+", version)][:4]
    if len(nums) == 1 or int(re.findall(r"\d+", version)[0]) > 65535:
        nums = [int(x) for x in time.strftime("%Y %m %d").split()]
    nums += [0] * (4 - len(nums))
    path = os.path.join(WORK, "version_info.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={tuple(nums)}, prodvers={tuple(nums)}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1,
                    subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
          StringStruct('FileDescription', 'Pico USB Sniffer'), StringStruct('ProductName', 'Pico USB Sniffer'),
          StringStruct('FileVersion', '{version}'), StringStruct('ProductVersion', '{version}'),
          StringStruct('OriginalFilename', '{NAME}.exe')])]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])])])
""")
    return path


def build(onefile, version):
    """-> path of the built .exe"""
    step("PyInstaller: " + ("single exe" if onefile else "folder"))
    base = os.path.join(WORK, "onefile" if onefile else "onedir")
    if os.path.isdir(base):
        shutil.rmtree(base)
    os.makedirs(base)
    dist = os.path.join(base, "dist")
    run([VPY, "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed", "--onefile" if onefile else "--onedir",
         "--name", NAME, "--paths", HERE, "--hidden-import", "serial.tools.list_ports_windows",
         "--icon", ICON, "--add-data", ICON + os.pathsep + ".",
         "--version-file", version_file(version), "--distpath", dist, "--workpath", os.path.join(base, "work"),
         "--specpath", base, "--log-level", "ERROR", MAIN], "PyInstaller", cwd=base)
    exe = os.path.join(dist, NAME + ".exe") if onefile else os.path.join(dist, NAME, NAME + ".exe")
    if not os.path.exists(exe):
        raise BuildError(f"{exe} was not created")
    return exe


def smoke_test(exe, onefile):
    """start a copy in demo mode, without Python in PATH, and wait for a growing capture"""
    step("Testing the exe (demo capture)")
    tmp = tempfile.mkdtemp(prefix="exe test ", dir=WORK)  # a blank in the path on purpose
    proc = None
    try:
        app = os.path.join(tmp, "app")
        if onefile:
            os.makedirs(app)
            shutil.copy2(exe, app)
        else:
            shutil.copytree(os.path.dirname(exe), app)
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PYTHON", "QT_", "VIRTUAL_ENV", "_PYI"))}
        win = os.environ.get("SystemRoot", r"C:\Windows")
        env["PATH"] = os.path.join(win, "System32") + ";" + win
        env["QT_QPA_PLATFORM"] = "offscreen"  # no window pops up
        proc = subprocess.Popen([os.path.join(app, NAME + ".exe"), "--demo"], cwd=tmp, env=env)
        cap_dir = os.path.join(app, "captures")
        t0 = time.monotonic()
        size = 0
        while time.monotonic() - t0 < SMOKE_TIMEOUT:
            time.sleep(0.5)
            if proc.poll() is not None:
                raise BuildError(f"the exe ended by itself (exit code {proc.returncode})")
            if os.path.exists(os.path.join(app, "error.log")):
                raise BuildError("the exe reported an error:\n" +
                                 open(os.path.join(app, "error.log"), encoding="utf-8", errors="replace").read())
            files = [f for f in os.listdir(cap_dir) if f.endswith(".pusb")] if os.path.isdir(cap_dir) else []
            size = os.path.getsize(os.path.join(cap_dir, files[0])) if files else 0
            if size > 20_000:
                print(f"OK: {size:,} bytes captured after {time.monotonic() - t0:.1f} s")
                return
        raise BuildError(f"no demo capture after {SMOKE_TIMEOUT} s ({size} bytes)")
    finally:
        if proc is not None and proc.poll() is None:
            # /T: a single exe runs as two processes
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            proc.wait(20)
        for _ in range(10):
            shutil.rmtree(tmp, ignore_errors=True)
            if not os.path.exists(tmp):
                break
            time.sleep(0.5)


def make_zip(exe, path):
    src = os.path.dirname(exe)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for d, _dirs, files in os.walk(src):
            for f in files:
                p = os.path.join(d, f)
                z.write(p, NAME + "/" + os.path.relpath(p, src).replace("\\", "/"))
        if os.path.exists(GUIDE):
            z.write(GUIDE, NAME + "/" + os.path.basename(GUIDE))
        if UF2:
            z.write(UF2, NAME + "/firmware/usb_sniffer.uf2")
        else:
            print("WARNING: no firmware in the package (firmware/build/usb_sniffer.uf2 not found)")


def publish(write, path):
    """write to a temporary name first: the output folder never holds a half written file"""
    part = path + ".part"
    try:
        write(part)
        os.replace(part, path)
    finally:
        if os.path.exists(part):
            os.remove(part)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return path, os.path.getsize(path), h.hexdigest()


def main():
    ap = argparse.ArgumentParser(prog="build_exe", description="Build the stand-alone Pico USB Sniffer program.")
    ap.add_argument("--mode", choices=("exe", "zip", "both"), default="both",
                    help="exe: one .exe file, zip: folder package, both (default)")
    ap.add_argument("--version", default=time.strftime("%Y%m%d_%H%M"), help="default: date_time")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"), help="output folder (default: ../dist)")
    ap.add_argument("--skip-tests", action="store_true", help="do not run tests/test_pipeline.py first")
    ap.add_argument("--clean", action="store_true", help="rebuild the build environment from scratch")
    a = ap.parse_args()
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", a.version) or not re.search(r"\d", a.version):
        ap.error("--version: use letters, digits, '.', '_' or '-', with at least one digit")
    out = os.path.abspath(a.out)
    modes = [m for m in ("zip", "exe") if a.mode in (m, "both")]
    target = {"zip": os.path.join(out, f"{NAME}_win64_{a.version}.zip"),
              "exe": os.path.join(out, f"{NAME}_{a.version}.exe")}
    for m in modes:
        if os.path.exists(target[m]):
            ap.error(f"{target[m]} already exists, choose another --version")

    t0 = time.monotonic()
    done = []
    try:
        if sys.platform != "win32":
            raise BuildError("this builds a Windows program, run it on Windows")
        if sys.version_info < MIN_PY:
            raise BuildError(f"Python {MIN_PY[0]}.{MIN_PY[1]} or newer is required, this is {sys.version.split()[0]}")
        os.makedirs(out, exist_ok=True)
        prepare_env(a.clean)
        if not a.skip_tests:
            step("Tests")
            run([VPY, TESTS], "The test suite (nothing was built)")
        for m in modes:
            exe = build(m == "exe", a.version)
            smoke_test(exe, m == "exe")
            done.append(publish((lambda p: shutil.copy2(exe, p)) if m == "exe" else (lambda p: make_zip(exe, p)),
                                target[m]))
    except (BuildError, OSError, subprocess.SubprocessError) as e:
        print(f"\nBUILD FAILED: {e}")
        return 1
    finally:
        for path, size, digest in done:
            print(f"\n{path}\n  {size / 1e6:.1f} MB  sha256 {digest}")
    print(f"\nBUILD OK ({time.monotonic() - t0:.0f} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
