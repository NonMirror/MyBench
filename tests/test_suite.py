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


class MyBenchSuiteTests(unittest.TestCase):
    def _fixture(self, root: Path) -> Path:
        ctf = root / "CTFbench"
        ctf.mkdir(parents=True)
        (ctf / "development_dataset.json").write_text(
            json.dumps({"fixture-pwn": {"category": "pwn", "path": "development/x/pwn/demo"}})
        )
        (ctf / "test_dataset.json").write_text("{}")
        challenge = ctf / "development/x/pwn/demo"
        challenge.mkdir(parents=True)
        (challenge / "challenge.json").write_text(
            json.dumps({"name": "demo", "category": "pwn", "flag": "flag{hidden}", "files": ["demo.c"]})
        )
        (challenge / "demo.c").write_text("int main(void) { return 0; }\n")
        return ctf

    def test_generation_and_validation_are_automatic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf = self._fixture(root)
            seeds = discover(ctf, "all", ("pwn", "rev"))
            self.assertEqual(len(seeds), 1)
            out = root / "out"
            created = generate(seeds, out)
            self.assertEqual(len(created), 1)
            report = validate_tree(out)
            self.assertEqual(report["status"], "passed")
            public = json.loads((created[0] / "challenge.json").read_text())
            self.assertNotIn("flag", public)
            source = (created[0] / "demo.c").read_text()
            self.assertIn("mybench_opaque_guard_", source)
            self.assertIn("if (mybench_opaque_guard_", source)
            self.assertNotIn("MYBENCH_AUTOMATED_MUTATION", source)
            manifest = json.loads((created[0] / "mutation_manifest.json").read_text())
            self.assertEqual(manifest["operations"][0]["operator"], "opaque_guard_injection")
            self.assertTrue((created[0] / "variant_runtime.json").exists())

    def test_unsupported_entrypoint_is_explicitly_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf = root / "CTFbench"
            challenge = ctf / "development/x/rev/library"
            challenge.mkdir(parents=True)
            (ctf / "development_dataset.json").write_text(
                json.dumps({"fixture-rev": {"category": "rev", "path": "development/x/rev/library"}})
            )
            (ctf / "test_dataset.json").write_text("{}")
            (challenge / "challenge.json").write_text(
                json.dumps({"name": "library", "category": "rev", "files": ["helper.c"]})
            )
            original = "#define HELPER_VALUE 7\n"
            (challenge / "helper.c").write_text(original)

            seeds = discover(ctf, "all", ("pwn", "rev"))
            created = generate(seeds, root / "out")
            manifest = json.loads((created[0] / "mutation_manifest.json").read_text())
            source_op = manifest["operations"][0]
            self.assertEqual(source_op["operator"], "source_mutation_skipped")
            self.assertIn("function definition", source_op["reason"])
            self.assertEqual((created[0] / "helper.c").read_text(), original)
            self.assertEqual(validate_tree(root / "out")["status"], "passed")

    def test_matching_executable_is_rebuilt(self) -> None:
        compiler = shutil.which("gcc")
        if not compiler:
            self.skipTest("gcc is required for the artifact rebuild fixture")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf = self._fixture(root)
            challenge = ctf / "development/x/pwn/demo"
            subprocess.run([compiler, str(challenge / "demo.c"), "-o", str(challenge / "demo")], check=True)
            metadata = json.loads((challenge / "challenge.json").read_text())
            metadata["files"].append("demo")
            (challenge / "challenge.json").write_text(json.dumps(metadata))

            seeds = discover(ctf, "all", ("pwn", "rev"))
            out = root / "out"
            created = generate(seeds, out)
            manifest = json.loads((created[0] / "mutation_manifest.json").read_text())
            rebuild = next(op for op in manifest["operations"] if op["operator"] == "compiled_artifact_rebuild")
            self.assertTrue(rebuild["changed"])
            self.assertNotEqual(rebuild["before_sha256"], rebuild["after_sha256"])
            self.assertEqual(validate_tree(out)["status"], "passed")

    def test_prebuilt_entrypoint_gets_real_cfg_mutation_when_no_source_is_available(self) -> None:
        compiler = shutil.which("gcc")
        if not compiler or not shutil.which("r2"):
            self.skipTest("gcc and radare2 are required for the binary CFG mutation fixture")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ctf = root / "CTFbench"
            challenge = ctf / "development/x/rev/prebuilt"
            challenge.mkdir(parents=True)
            (ctf / "development_dataset.json").write_text(
                json.dumps({"fixture-prebuilt": {"category": "rev", "path": "development/x/rev/prebuilt"}})
            )
            (ctf / "test_dataset.json").write_text("{}")
            (challenge / "challenge.json").write_text(
                json.dumps({"name": "prebuilt", "category": "rev", "files": ["prebuilt"]})
            )
            source = root / "prebuilt.c"
            source.write_text(
                "#include <stdio.h>\n"
                "int main(int argc, char **argv) {\n"
                "  if (argc > 1) puts(argv[1]);\n"
                "  return 0;\n"
                "}\n"
            )
            subprocess.run([compiler, "-O0", str(source), "-o", str(challenge / "prebuilt")], check=True)

            seeds = discover(ctf, "all", ("pwn", "rev"))
            out = root / "out"
            created = generate(seeds, out)
            manifest = json.loads((created[0] / "mutation_manifest.json").read_text())
            binary_op = next(
                op for op in manifest["operations"] if op["operator"] == "binary_cfg_mutation"
            )
            self.assertTrue(binary_op["changed"])
            self.assertNotEqual(binary_op["before_sha256"], binary_op["after_sha256"])
            self.assertNotEqual(binary_op["cfg_before"], binary_op["cfg_after"])
            report = validate_tree(out)
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["substantive_artifact_mutations"], 1)


if __name__ == "__main__":
    unittest.main()
