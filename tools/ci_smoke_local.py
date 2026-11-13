"""Run the build's smoke-test steps locally, exactly as .github/workflows/
build.yml has them, against the script instead of the frozen binary.

    python3 tools/ci_smoke_local.py

Every step named "Smoke-test ..." that runs with bash (not the Windows-only
PowerShell one) is taken from build.yml as it stands and run with GitHub's
own bash options (-eo pipefail) in a fresh temporary copy of the
repository. "./out/<asset>" is a small wrapper that starts
chromiq_io_probe.py from out/, so a report lands in out/ as with the
binary. Prints one PASS / FAIL line per step; exit code 1 if any failed.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSET = "chromiq-io-probe-local"


def smoke_steps(text):
    """[(name, condition, shell, script)] for every Smoke-test step."""
    lines = text.splitlines()
    steps = []
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)- name: (Smoke-test.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent, name = len(m.group(1)), m.group(2)
        cond, shell, script = "", "bash", []
        i += 1
        while i < len(lines) and not re.match(r"^\s*- (name|uses):", lines[i]):
            line = lines[i]
            if re.match(r"^\s+if:", line):
                cond = line.split("if:", 1)[1].strip()
            elif re.match(r"^\s+shell:", line):
                shell = line.split("shell:", 1)[1].strip()
            elif re.match(r"^\s+run: \|", line):
                run_indent = len(line) - len(line.lstrip())
                i += 1
                while i < len(lines) and (not lines[i].strip() or
                                          len(lines[i]) - len(lines[i].lstrip()) > run_indent):
                    script.append(lines[i][run_indent + 2:])
                    i += 1
                continue
            elif line.strip() and len(line) - len(line.lstrip()) <= indent - 2:
                break
            i += 1
        steps.append((name, cond, shell, "\n".join(script)))
    return steps


def main():
    with open(os.path.join(ROOT, ".github", "workflows", "build.yml"), encoding="utf-8") as fh:
        steps = smoke_steps(fh.read())
    runner_os = {"Darwin": "macOS", "Linux": "Linux"}.get(os.uname().sysname, "Linux")
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = os.path.join(tmp, "repo")
        shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        out = os.path.join(work, "out")
        os.makedirs(out)
        shutil.copy(os.path.join(work, "chromiq_io_probe.py"), out)
        wrapper = os.path.join(out, ASSET)
        with open(wrapper, "w") as fh:
            fh.write('#!/bin/sh\nexec "%s" "$(dirname "$0")/chromiq_io_probe.py" "$@"\n'
                     % sys.executable)
        os.chmod(wrapper, 0o755)
        for name, cond, shell, script in steps:
            if shell != "bash" or "== 'Windows'" in cond:
                print(f"SKIP  {name} (Windows only)")
                continue
            script = (script.replace("${{ matrix.asset }}", ASSET)
                      .replace("${{ runner.os }}", runner_os))
            env = dict(os.environ, PATH=os.path.dirname(sys.executable) + os.pathsep
                       + os.environ.get("PATH", ""))
            proc = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                                   script], cwd=work, env=env, stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=600)
            ok = proc.returncode == 0
            failed += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {name} (exit {proc.returncode})")
            if not ok:
                print("      " + (proc.stdout + proc.stderr)[-1500:].replace("\n", "\n      "))
    print(f"smoke steps: {len([s for s in steps if s[2] == 'bash'])} run, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
