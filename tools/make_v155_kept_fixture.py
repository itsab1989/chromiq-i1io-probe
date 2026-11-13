"""Write tests/fixtures/v155-kept.json: what the tagged v1.5.5 keeps from the
recordings in tests/regression_recordings.py, and what its --analyze says.

    python3 tools/make_v155_kept_fixture.py

Reads v1.5.5's chromiq_io_probe.py from git (git show v1.5.5:...), runs it in
a temporary folder, and never changes the working tree's tool.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))


def main():
    src = subprocess.run(["git", "show", "v1.5.5:chromiq_io_probe.py"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "probe_v155.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src)
        spec = importlib.util.spec_from_file_location("probe_v155", path)
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        sys.modules["chromiq_io_probe"] = old          # synth imports it by name
        import regression_recordings as rr             # noqa: PLC0415
        files = rr.save_all(os.path.join(tmp, "rec"))
        out = {"version": old.PROBE_VERSION, "copies": {}, "analysis": {}}
        for name, rec in files.items():
            out["copies"][name] = rr.outcome(old, rec, tmp)
            out["analysis"][name] = rr.analysis_outcome(old, rec)
    dst = os.path.join(ROOT, "tests", "fixtures", "v155-kept.json")
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote", dst)


if __name__ == "__main__":
    main()
