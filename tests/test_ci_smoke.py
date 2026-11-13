"""1.6, third review: the build's analyser smoke-test steps, exactly as
.github/workflows/build.yml has them, run against the script.

    python3 -m unittest discover -s tests -v

tools/ci_smoke_local.py reads the steps from build.yml (so an edit there
is tested as written) and runs them with GitHub's own bash options. The
step that runs the whole detection is left to that tool (it takes long);
the three analyser steps run here.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import ci_smoke_local  # noqa: E402


@unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "needs bash, as the CI step")
class AnalyserSmokeSteps(unittest.TestCase):

    def test_build_yml_has_the_steps(self):
        with open(os.path.join(ROOT, ".github", "workflows", "build.yml"), encoding="utf-8") as fh:
            names = [s[0] for s in ci_smoke_local.smoke_steps(fh.read())]
        for name in ("Smoke-test the analyser in the binary",
                     "Smoke-test the i1iO analysis in the binary",
                     "Smoke-test the i1iSis analysis in the binary"):
            self.assertIn(name, names)

    def test_the_analyser_steps_pass(self):
        with open(os.path.join(ROOT, ".github", "workflows", "build.yml"), encoding="utf-8") as fh:
            steps = [s for s in ci_smoke_local.smoke_steps(fh.read()) if "analys" in s[0]]
        self.assertEqual(len(steps), 3)
        with tempfile.TemporaryDirectory() as tmp:
            work = os.path.join(tmp, "repo")
            # The build has made out/ and smoke/ in the checkout before the
            # tests run (Python 3.8 step): never copy them.
            shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(
                ".git", "__pycache__", "out", "smoke", "build", "dist", "*.spec"))
            os.makedirs(os.path.join(work, "out"))
            wrapper = os.path.join(work, "out", "probe")
            with open(wrapper, "w") as fh:
                fh.write('#!/bin/sh\nexec "%s" "%s" "$@"\n'
                         % (sys.executable, os.path.join(work, "chromiq_io_probe.py")))
            os.chmod(wrapper, 0o755)
            env = dict(os.environ, PATH=os.path.dirname(sys.executable) + os.pathsep
                       + os.environ.get("PATH", ""))
            for name, _cond, _shell, script in steps:
                with self.subTest(step=name):
                    script = script.replace("${{ matrix.asset }}", "probe").replace(
                        "${{ runner.os }}", "Linux")
                    proc = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail",
                                           "-c", script], cwd=work, env=env,
                                          stdin=subprocess.DEVNULL, capture_output=True,
                                          text=True, timeout=300)
                    self.assertEqual(proc.returncode, 0, (proc.stdout + proc.stderr)[-1500:])


if __name__ == "__main__":
    unittest.main()
