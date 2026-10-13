from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from mybench.discovery import discover
from mybench.mutators import generate
from mybench.validator import validate_tree


NOISE = {
    "decoy_function_injection",
    "dead_code_injection",
    "duplicate_string_injection",
    "irrelevant_syscall_injection",
}
EXCLUDED = {"control_flow_flattening", "ollvm", "packing", "shell"}


class NoiseMutationTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path]:
        compiler = shutil.which("gcc")
        if not compiler:
            self.skipTest("gcc is required")
        ctf = root / "CTFbench"
        challenge = ctf / "development/x/pwn/noise"
        challenge.mkdir(parents=True)
        (ctf / "development_dataset.json").write_text(json.dumps({"noise": {"category": "pwn", "path": "development/x/pwn/noise"}}))
        (ctf / "test_dataset.json").write_text("{}")
        (challenge / "challenge.json").write_text(json.dumps({"name": "noise", "category": "pwn", "flag": "flag{hidden}", "files": ["noise.c"]}))
        source = challenge / "noise.c"
        source.write_text('#include <stdio.h>\nint main(void) { puts("stable-output"); return 0; }\n')
        binary = challenge / "noise"
        subprocess.run([compiler, "-O0", "-g0", str(source), "-o", str(binary)], check=True)
        metadata = json.loads((challenge / "challenge.json").read_text())
        metadata["files"].append("noise")
        (challenge / "challenge.json").write_text(json.dumps(metadata))
        return ctf, challenge

    def test_noise_reaches_deployed_artifact_and_preserves_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf, challenge = self.fixture(root)
            expected = subprocess.run([str(challenge / "noise")], check=True, text=True, stdout=subprocess.PIPE).stdout
            variant = generate(discover(ctf), root / "out")[0]
            manifest = json.loads((variant / "mutation_manifest.json").read_text())
            policy = manifest["noise_policy"]
            self.assertTrue(NOISE.issubset(set(policy["enabled_operators"])))
            self.assertTrue(EXCLUDED.issubset(set(policy["excluded_techniques"])))
            operations = {op["operator"]: op for op in manifest["operations"] if op.get("operator") in NOISE}
            self.assertEqual(set(operations), NOISE)
            source_text = (variant / "noise.c").read_text()
            for name, operation in operations.items():
                self.assertTrue(operation["changed"], name)
                self.assertNotEqual(operation["before_sha256"], operation["after_sha256"])
                self.assertIn(operation["marker"], source_text)
            self.assertEqual(subprocess.run([str(variant / "noise")], check=True, text=True, stdout=subprocess.PIPE).stdout, expected)
            self.assertEqual(validate_tree(root / "out")["status"], "passed")

    def test_zero_limits_are_recorded_as_skips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf, _ = self.fixture(root)
            policy = {
                "enabled_operators": sorted(NOISE),
                "excluded_techniques": sorted(EXCLUDED),
                "limits": {"max_decoy_functions": 0, "max_dead_code_blocks": 0, "max_duplicate_strings": 0, "max_irrelevant_syscalls": 0},
            }
            variant = generate(discover(ctf), root / "out", noise_policy=policy)[0]
            manifest = json.loads((variant / "mutation_manifest.json").read_text())
            operations = [op for op in manifest["operations"] if op.get("operator") in NOISE]
            self.assertEqual(len(operations), 4)
            self.assertTrue(all(not op["changed"] for op in operations))
            self.assertEqual(validate_tree(root / "out")["status"], "passed")


if __name__ == "__main__":
    unittest.main()
