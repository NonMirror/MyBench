from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from mybench.project_builds import (
    execute_project_build,
    go_dockerfile_plan,
    rust_cargo_plan,
)


class ProjectBuildTests(unittest.TestCase):
    def test_rust_plan_uses_locked_cargo_package_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text(
                '[package]\nname = "sample-bin"\nversion = "0.1.0"\nedition = "2021"\n'
            )
            # A dependency-free lockfile is sufficient for Cargo's offline
            # locked mode and keeps this test independent of a registry cache.
            (root / "Cargo.lock").write_text("version = 3\n\n[[package]]\nname = \"sample-bin\"\nversion = \"0.1.0\"\n")
            source = root / "src/main.rs"
            source.write_text('fn main() { println!("stable"); }\n')
            plan = rust_cargo_plan(root, source)
            if not shutil.which("cargo"):
                self.skipTest("cargo is required")
            self.assertIsNotNone(plan)
            assert plan is not None
            self.assertEqual(plan.artifact_name, "sample-bin")
            self.assertEqual(plan.source_files, (Path("src/main.rs"),))
            self.assertIn("--offline", plan.command)
            self.assertIn("--locked", plan.command)
            with tempfile.TemporaryDirectory() as output_dir:
                output = Path(output_dir) / "sample-bin"
                result = execute_project_build(plan, output)
                self.assertTrue(result.changed, result.reason)
                self.assertTrue(output.is_file())
                self.assertEqual(
                    subprocess.run([str(output)], check=True, text=True, stdout=subprocess.PIPE).stdout,
                    "stable\n",
                )
            self.assertFalse((root / "target").exists())
            self.assertEqual(source.read_text(), 'fn main() { println!("stable"); }\n')

    def test_rust_plan_requires_lockfile_and_explicit_root_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text('[package]\nname = "sample"\nversion = "0.1.0"\n')
            source = root / "src/main.rs"
            source.write_text("fn main() {}\n")
            self.assertIsNone(rust_cargo_plan(root, source))
            (root / "Cargo.lock").write_text("version = 3\n")
            # A source outside the package root is never guessed into it.
            external = root.parent / "outside.rs"
            external.write_text("fn main() {}\n")
            try:
                self.assertIsNone(rust_cargo_plan(root, external))
            finally:
                external.unlink()

    def test_go_plan_requires_explicit_dockerfile_build_and_lists_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text(
                "FROM golang:1.20\n"
                "RUN go build -o /home/gopherz/gopherz gopher.go enc.go\n"
            )
            (root / "gopher.go").write_text("package main\n")
            (root / "enc.go").write_text("package main\n")
            plan = go_dockerfile_plan(root)
            if not shutil.which("go"):
                self.skipTest("go is required")
            self.assertIsNotNone(plan)
            assert plan is not None
            self.assertEqual(plan.artifact_name, "gopherz")
            self.assertEqual(plan.source_files, (Path("gopher.go"), Path("enc.go")))
            self.assertEqual(plan.kind, "dockerfile-go-build")
            self.assertEqual(plan.command[-2:], ("gopher.go", "enc.go"))

    def test_gopherz_dockerfile_has_no_build_evidence(self) -> None:
        root = Path(__file__).parents[1] / "../CTFbench/test/2017/CSAW-Quals/rev/gopherz"
        root = root.resolve()
        self.assertTrue((root / "Dockerfile").is_file())
        # The seed Dockerfile copies a prebuilt gopherz executable.  A plan must
        # not infer `go build gopher.go enc.go` from source files alone.
        self.assertIsNone(go_dockerfile_plan(root))


if __name__ == "__main__":
    unittest.main()
