from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional

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


def _go_tool() -> Optional[str]:
    """Find Go even when the mise shim refuses an untrusted local config."""
    candidates = []
    resolved = shutil.which("go")
    if resolved:
        candidates.append(Path(resolved))
    candidates.append(Path("/usr/local/go/bin/go"))
    mise_root = Path.home() / ".local/share/mise/installs/go"
    if mise_root.is_dir():
        candidates.extend(sorted(mise_root.glob("*/bin/go"), reverse=True))
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_mode & 0o111:
            try:
                if subprocess.run(
                    [str(candidate), "version"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                ).returncode == 0:
                    return str(candidate)
            except (OSError, subprocess.TimeoutExpired):
                continue
    return None


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

    def test_python_source_supports_all_noise_operators(self) -> None:
        """Interpreted challenge entrypoints must not be language skips."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf = root / "CTFbench"
            challenge = ctf / "development/x/rev/python_noise"
            challenge.mkdir(parents=True)
            (ctf / "development_dataset.json").write_text(
                json.dumps({"python-noise": {"category": "rev", "path": "development/x/rev/python_noise"}})
            )
            (ctf / "test_dataset.json").write_text("{}")
            (challenge / "challenge.json").write_text(
                json.dumps({"name": "python_noise", "category": "rev", "files": ["noise.py"]})
            )
            source = challenge / "noise.py"
            source.write_text("#!/usr/bin/python3\nprint('stable-python')\n")
            source.chmod(0o755)
            variant = generate(discover(ctf), root / "out")[0]
            manifest = json.loads((variant / "mutation_manifest.json").read_text())
            operations = {op["operator"]: op for op in manifest["operations"] if op.get("operator") in NOISE}
            self.assertEqual(set(operations), NOISE)
            text = (variant / "noise.py").read_text()
            for name, operation in operations.items():
                self.assertTrue(operation["changed"], name)
                self.assertIn(operation["marker"], text)
            self.assertEqual(
                subprocess.run([sys.executable, str(variant / "noise.py")], check=True, text=True, stdout=subprocess.PIPE).stdout,
                "stable-python\n",
            )
            self.assertEqual(validate_tree(root / "out")["status"], "passed")

    def test_go_source_supports_all_noise_operators(self) -> None:
        """Go source gets parseable module-level noise, including guarded Getpid."""
        if not _go_tool():
            self.skipTest("Go is required for Go noise validation")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf = root / "CTFbench"
            challenge = ctf / "development/x/rev/go_noise"
            challenge.mkdir(parents=True)
            (ctf / "development_dataset.json").write_text(
                json.dumps({"go-noise": {"category": "rev", "path": "development/x/rev/go_noise"}})
            )
            (ctf / "test_dataset.json").write_text("{}")
            (challenge / "challenge.json").write_text(
                json.dumps({"name": "go_noise", "category": "rev", "files": ["noise.go"]})
            )
            (challenge / "noise.go").write_text(
                'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("stable-go") }\n'
            )
            variant = generate(discover(ctf), root / "out")[0]
            manifest = json.loads((variant / "mutation_manifest.json").read_text())
            operations = {op["operator"]: op for op in manifest["operations"] if op.get("operator") in NOISE}
            self.assertEqual(set(operations), NOISE)
            text = (variant / "noise.go").read_text()
            self.assertIn('import "os"', text)
            for name, operation in operations.items():
                self.assertTrue(operation["changed"], name)
                self.assertIn(operation["marker"], text)
            self.assertEqual(validate_tree(root / "out")["status"], "passed")

    def test_go_source_rebuilds_a_matching_deployed_artifact(self) -> None:
        """A same-basename Go binary receives the source mutation in-place."""
        go = _go_tool()
        if not go:
            self.skipTest("go is required for Go artifact rebuild validation")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf = root / "CTFbench"
            challenge = ctf / "development/x/rev/go_binary"
            challenge.mkdir(parents=True)
            (ctf / "development_dataset.json").write_text(
                json.dumps({"go-binary": {"category": "rev", "path": "development/x/rev/go_binary"}})
            )
            (ctf / "test_dataset.json").write_text("{}")
            (challenge / "challenge.json").write_text(
                json.dumps({"name": "go_binary", "category": "rev", "files": ["noise.go", "noise"]})
            )
            source = challenge / "noise.go"
            source.write_text(
                'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("stable-go") }\n'
            )
            original = challenge / "noise"
            subprocess.run([go, "build", "-o", str(original), str(source)], check=True)
            expected = subprocess.run([str(original)], check=True, text=True, stdout=subprocess.PIPE).stdout
            variant = generate(discover(ctf), root / "out")[0]
            manifest = json.loads((variant / "mutation_manifest.json").read_text())
            rebuild = next(
                op for op in manifest["operations"] if op.get("operator") == "compiled_artifact_rebuild"
            )
            self.assertTrue(rebuild["changed"])
            self.assertNotEqual(rebuild["before_sha256"], rebuild["after_sha256"])
            artifact_bytes = (variant / "noise").read_bytes()
            for operator in NOISE | {"opaque_guard_injection"}:
                marker = next(op["marker"] for op in manifest["operations"] if op.get("operator") == operator)
                self.assertIn(marker.encode(), artifact_bytes, operator)
            self.assertEqual(
                subprocess.run([str(variant / "noise")], check=True, text=True, stdout=subprocess.PIPE).stdout,
                expected,
            )
            self.assertEqual(validate_tree(root / "out")["status"], "passed")


    def test_rust_source_supports_all_noise_operators(self) -> None:
        if not shutil.which("rustc"):
            self.skipTest("rustc is required for Rust noise validation")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf = root / "CTFbench"
            challenge = ctf / "development/x/rev/rust_noise"
            challenge.mkdir(parents=True)
            (ctf / "development_dataset.json").write_text(
                json.dumps({"rust-noise": {"category": "rev", "path": "development/x/rev/rust_noise"}})
            )
            (ctf / "test_dataset.json").write_text("{}")
            (challenge / "challenge.json").write_text(
                json.dumps({"name": "rust_noise", "category": "rev", "files": ["main.rs"]})
            )
            (challenge / "main.rs").write_text('fn main() { println!("stable-rust"); }\n')
            variant = generate(discover(ctf), root / "out")[0]
            manifest = json.loads((variant / "mutation_manifest.json").read_text())
            operations = {op["operator"]: op for op in manifest["operations"] if op.get("operator") in NOISE}
            self.assertEqual(set(operations), NOISE)
            text = (variant / "main.rs").read_text()
            for name, operation in operations.items():
                self.assertTrue(operation["changed"], name)
                self.assertIn(operation["marker"], text)
            self.assertEqual(validate_tree(root / "out")["status"], "passed")

    def test_java_source_supports_all_noise_operators(self) -> None:
        if not shutil.which("javac"):
            self.skipTest("javac is required for Java noise validation")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf = root / "CTFbench"
            challenge = ctf / "development/x/rev/java_noise"
            challenge.mkdir(parents=True)
            (ctf / "development_dataset.json").write_text(
                json.dumps({"java-noise": {"category": "rev", "path": "development/x/rev/java_noise"}})
            )
            (ctf / "test_dataset.json").write_text("{}")
            (challenge / "challenge.json").write_text(
                json.dumps({"name": "java_noise", "category": "rev", "files": ["Noise.java"]})
            )
            (challenge / "Noise.java").write_text(
                'public class Noise { public static void main(String[] args) { System.out.println("stable-java"); } }\n'
            )
            variant = generate(discover(ctf), root / "out")[0]
            manifest = json.loads((variant / "mutation_manifest.json").read_text())
            operations = {op["operator"]: op for op in manifest["operations"] if op.get("operator") in NOISE}
            self.assertEqual(set(operations), NOISE)
            text = (variant / "Noise.java").read_text()
            for name, operation in operations.items():
                self.assertTrue(operation["changed"], name)
                self.assertIn(operation["marker"], text)
            self.assertEqual(validate_tree(root / "out")["status"], "passed")


if __name__ == "__main__":
    unittest.main()
