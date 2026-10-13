from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Optional

from mybench.mutators import SOURCE_NOISE_OPERATORS, _mutate_source, _mutate_source_noise


class CompiledLanguageMutationTests(unittest.TestCase):
    @staticmethod
    def _tool(name: str) -> Optional[str]:
        system_tool = Path("/usr/bin") / name
        return str(system_tool) if system_tool.exists() else shutil.which(name)

    def _apply_all(self, source: Path, suffix: str):
        relative = Path(source.name)
        operations = [_mutate_source(source, relative, f"compiled_{suffix}")]
        operations.extend(_mutate_source_noise(source, relative, f"compiled_{suffix}"))
        return operations

    def test_rust_markers_survive_compile_and_output_is_unchanged(self) -> None:
        rustc = shutil.which("rustc")
        if not rustc:
            self.skipTest("rustc is required")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "main.rs"
            source.write_text(
                '#![allow(dead_code)]\nfn main() { println!("stable-rust"); }\n',
                encoding="utf-8",
            )
            operations = self._apply_all(source, "rust")
            markers = [op["marker"] for op in operations if op["operator"] in ("opaque_guard_injection", *SOURCE_NOISE_OPERATORS)]
            artifact = root / "main"
            subprocess.run([rustc, "--edition=2021", str(source), "-o", str(artifact)], check=True)
            result = subprocess.run([str(artifact)], check=True, text=True, stdout=subprocess.PIPE)
            self.assertEqual(result.stdout, "stable-rust\n")
            nm = shutil.which("nm")
            symbols = (
                subprocess.run([nm, "-a", str(artifact)], check=False, text=True, stdout=subprocess.PIPE).stdout
                if nm else ""
            )
            data = artifact.read_bytes().decode("latin1")
            for marker in markers:
                self.assertTrue(marker in symbols or marker in data, marker)

    def test_java_markers_survive_compile_and_output_is_unchanged(self) -> None:
        javac = self._tool("javac")
        java = self._tool("java")
        if not javac or not java:
            self.skipTest("javac and java are required")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Main.java"
            source.write_text(
                "public class Main {\n"
                "  static class Nested { int value() { return 1; } }\n"
                "  public static void main(String[] args) { System.out.println(\"stable-java\"); }\n"
                "}\n// trailing brace-looking comment: }\n",
                encoding="utf-8",
            )
            operations = self._apply_all(source, "java")
            markers = [op["marker"] for op in operations if op["operator"] in ("opaque_guard_injection", *SOURCE_NOISE_OPERATORS)]
            classes = root / "classes"
            classes.mkdir()
            subprocess.run([javac, "-d", str(classes), str(source)], check=True)
            result = subprocess.run(
                [java, "-cp", str(classes), "Main"], check=True, text=True, stdout=subprocess.PIPE
            )
            self.assertEqual(result.stdout, "stable-java\n")
            class_data = b"".join(path.read_bytes() for path in classes.rglob("*.class"))
            for marker in markers:
                self.assertIn(marker.encode(), class_data, marker)


if __name__ == "__main__":
    unittest.main()
