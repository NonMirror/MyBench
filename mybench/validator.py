from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .mutators import OPAQUE_GUARD_PREFIX, _cfg_witness, sha256_file


def _run(command: List[str], cwd: Path, timeout: int) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": command,
            "returncode": proc.returncode,
            "output": proc.stdout[-4000:],
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "command": command,
            "returncode": None,
            "output": str(exc),
            "duration_seconds": round(time.monotonic() - started, 3),
        }


def _syntax_check(variant_dir: Path, source_rel: str) -> Dict[str, Any]:
    source = variant_dir / source_rel
    suffix = source.suffix.lower()
    if suffix in {".c", ".cc", ".cpp", ".cxx"}:
        compiler = shutil.which("g++" if suffix in {".cc", ".cpp", ".cxx"} else "gcc")
        if not compiler:
            return {"status": "skipped", "reason": "compiler unavailable"}
        include_dirs = sorted({str(p.parent) for p in variant_dir.rglob("*") if p.is_dir()})
        command = [compiler, "-fsyntax-only", "-fcommon"]
        command.extend(f"-I{p}" for p in include_dirs[:80])
        command.append(str(source))
    elif suffix == ".py":
        # Compile in memory so validation does not leave pyc artifacts in the
        # generated variant tree.
        command = [
            sys.executable,
            "-c",
            "import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'), sys.argv[1], 'exec')",
            str(source),
        ]
    elif suffix == ".go":
        gofmt = shutil.which("gofmt")
        if not gofmt:
            return {"status": "skipped", "reason": "gofmt unavailable"}
        command = [gofmt, "-d", str(source)]
    else:
        return {"status": "skipped", "reason": f"no syntax checker for {suffix or 'unknown'}"}
    result = _run(command, variant_dir, timeout=20)
    # gofmt uses exit code 1 to report formatting differences while still
    # successfully parsing the file; only an actual tool failure is a syntax
    # warning for this lightweight check.
    if suffix == ".go" and result["returncode"] == 1:
        result["status"] = "passed"
        result["formatting_diff"] = True
    else:
        result["status"] = "passed" if result["returncode"] == 0 else "warning"
    return result


def _break_hardlink(path: Path) -> None:
    """Make a declared artifact copy-on-write before a build can overwrite it."""
    if not path.is_file() or path.is_symlink():
        return
    temporary = path.with_name(path.name + ".mybench-cow")
    shutil.copy2(path, temporary)
    path.unlink()
    temporary.replace(path)


def _build_check(variant_dir: Path, declared_files: List[str], timeout: int = 90) -> Dict[str, Any]:
    makefile = next((p for p in (variant_dir / "Makefile", variant_dir / "makefile") if p.exists()), None)
    if makefile is None:
        return {"status": "skipped", "reason": "no Makefile"}
    # Never run an untrusted Makefile in the hard-linked output tree. A build
    # can rewrite generated headers, binaries, or chmod bits that are not listed
    # in challenge.json. Build in a fully detached temporary copy instead.
    scratch_parent = Path(tempfile.mkdtemp(prefix="mybench-build-"))
    scratch = scratch_parent / "variant"
    try:
        shutil.copytree(variant_dir, scratch, symlinks=True, copy_function=shutil.copy2)
        result = _run(["make", "-C", str(scratch), "-j2"], scratch, timeout)
    except (OSError, shutil.Error) as exc:
        result = {"command": ["make", "-C", str(scratch), "-j2"], "returncode": None, "output": str(exc)}
    finally:
        shutil.rmtree(scratch_parent, ignore_errors=True)
    result["status"] = "passed" if result["returncode"] == 0 else "warning"
    return result


def _binary_has_symbol(path: Path, symbol: str) -> bool:
    """Check for the injected symbol without requiring a particular objdump."""
    try:
        if symbol.encode("utf-8") in path.read_bytes():
            return True
    except OSError:
        return False
    nm = shutil.which("nm")
    if not nm:
        return False
    try:
        result = subprocess.run(
            [nm, "-a", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return symbol in result.stdout


def _binary_bytes_at(path: Path, address: int, length: int) -> Optional[bytes]:
    """Read bytes through radare2's virtual-address view for patch validation."""
    r2 = shutil.which("r2")
    if not r2 or length <= 0:
        return None
    try:
        result = subprocess.run(
            [r2, "-q", "-c", f"p8j {length} @ {address}; q", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in result.stdout.splitlines():
        candidate = line.strip()
        if not candidate.startswith("[") or not candidate.endswith("]"):
            continue
        try:
            values = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(values, list) and all(isinstance(value, int) for value in values):
            return bytes(values)
    return None


def validate_manifest(manifest_path: Path, build: bool = False) -> Dict[str, Any]:
    started = time.monotonic()
    errors: List[str] = []
    warnings: List[str] = []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    variant_dir = manifest_path.parent
    if manifest.get("schema_version") != 1:
        errors.append("unsupported or missing schema_version")
    if manifest.get("category") not in {"pwn", "rev"}:
        errors.append("variant category is not pwn/rev")
    challenge_path = variant_dir / "challenge.json"
    if not challenge_path.exists():
        errors.append("missing sanitized challenge.json")
    else:
        try:
            challenge = json.loads(challenge_path.read_text(encoding="utf-8"))
            if "flag" in challenge or "answer" in challenge:
                errors.append("public challenge metadata contains a secret field")
            if challenge.get("mybench_variant", {}).get("variant_id") != manifest.get("variant_id"):
                errors.append("challenge.json variant id does not match manifest")
        except json.JSONDecodeError as exc:
            errors.append(f"invalid challenge.json: {exc}")

    declared = manifest.get("seed_metadata", {}).get("declared_files", []) or []
    missing_declared = [rel for rel in declared if not (variant_dir / rel).exists()]
    if missing_declared:
        errors.append("declared files missing: " + ", ".join(missing_declared))

    operation_results: List[Dict[str, Any]] = []
    for operation in manifest.get("operations", []):
        rel = operation.get("path")
        if rel and operation.get("operator") == "opaque_guard_injection":
            path = variant_dir / rel
            if not path.exists():
                errors.append(f"mutated source missing: {rel}")
            else:
                after = sha256_file(path)
                if after != operation.get("after_sha256"):
                    errors.append(f"mutated source hash mismatch: {rel}")
                try:
                    text = path.read_text(encoding="utf-8")
                    marker = operation.get("marker")
                    if not marker or not str(marker).startswith(OPAQUE_GUARD_PREFIX) or str(marker) not in text:
                        errors.append(f"opaque guard symbol missing from source: {rel}")
                except UnicodeDecodeError:
                    warnings.append(f"mutated source is not UTF-8: {rel}")
                operation_results.append({"operator": operation.get("operator"), "path": rel, "status": "checked"})
        elif operation.get("operator") == "source_mutation_skipped":
            operation_results.append(
                {
                    "operator": operation.get("operator"),
                    "path": operation.get("path"),
                    "status": "skipped",
                    "reason": operation.get("reason", "unspecified"),
                }
            )
        elif operation.get("operator") == "compiled_artifact_rebuild":
            artifact = variant_dir / str(operation.get("path", ""))
            if not artifact.exists():
                errors.append(f"rebuilt artifact missing: {operation.get('path')}")
            else:
                after = sha256_file(artifact)
                if after != operation.get("after_sha256"):
                    errors.append(f"rebuilt artifact hash mismatch: {operation.get('path')}")
                if after == operation.get("before_sha256") or not operation.get("changed"):
                    errors.append(f"rebuilt artifact is byte-identical to seed: {operation.get('path')}")
                marker = operation.get("marker")
                if not marker or not _binary_has_symbol(artifact, str(marker)):
                    errors.append(f"rebuilt artifact lacks injected symbol: {operation.get('path')}")
                cfg_before = operation.get("cfg_before")
                cfg_function = operation.get("function_addr", operation.get("function", "main"))
                cfg_after = operation.get("cfg_after") or _cfg_witness(artifact, cfg_function)
                if cfg_before is not None and cfg_after is not None:
                    if cfg_before == cfg_after:
                        errors.append(f"rebuilt artifact CFG witness did not change: {operation.get('path')}")
                elif cfg_before is not None:
                    warnings.append(f"CFG witness unavailable for rebuilt artifact: {operation.get('path')}")
                operation_results.append(
                    {
                        "operator": operation.get("operator"),
                        "path": str(operation.get("path")),
                        "status": "checked",
                        "changed": bool(operation.get("changed")),
                        "cfg_before": cfg_before,
                        "cfg_after": cfg_after,
                    }
                )
        elif operation.get("operator") == "compiled_artifact_rebuild_skipped":
            warnings.append(
                "compiled artifact rebuild skipped for "
                + str(operation.get("source", operation.get("path", "unknown source")))
                + ": "
                + str(operation.get("reason", "unspecified"))
            )
            operation_results.append(
                {
                    "operator": operation.get("operator"),
                    "path": operation.get("path"),
                    "status": "skipped",
                    "reason": operation.get("reason", "unspecified"),
                }
            )
        elif operation.get("operator") == "binary_cfg_mutation":
            artifact = variant_dir / str(operation.get("path", ""))
            if not artifact.exists():
                errors.append(f"binary CFG mutation artifact missing: {operation.get('path')}")
            else:
                after = sha256_file(artifact)
                if after != operation.get("after_sha256"):
                    errors.append(f"binary CFG mutation hash mismatch: {operation.get('path')}")
                if after == operation.get("before_sha256") or not operation.get("changed"):
                    errors.append(f"binary CFG mutation is byte-identical to seed: {operation.get('path')}")
                address = operation.get("address")
                expected = operation.get("after_bytes")
                if isinstance(address, int) and isinstance(expected, str):
                    try:
                        expected_bytes = bytes.fromhex(expected)
                    except ValueError:
                        errors.append(f"invalid binary CFG patch bytes in manifest: {operation.get('path')}")
                    else:
                        actual = _binary_bytes_at(artifact, address, len(expected_bytes))
                        if actual is not None and actual.hex() != expected:
                            errors.append(f"binary CFG patch bytes do not match manifest: {operation.get('path')}")
                cfg_before = operation.get("cfg_before")
                cfg_function = operation.get("function_addr", operation.get("function", "main"))
                cfg_after = operation.get("cfg_after") or _cfg_witness(artifact, cfg_function)
                if cfg_before is not None and cfg_after is not None:
                    if cfg_before == cfg_after:
                        errors.append(f"binary CFG witness did not change: {operation.get('path')}")
                else:
                    warnings.append(f"CFG witness unavailable for binary mutation: {operation.get('path')}")
                operation_results.append(
                    {
                        "operator": operation.get("operator"),
                        "path": str(operation.get("path")),
                        "status": "checked",
                        "changed": bool(operation.get("changed")),
                        "cfg_before": cfg_before,
                        "cfg_after": cfg_after,
                    }
                )
        elif operation.get("operator") == "binary_cfg_mutation_skipped":
            warnings.append(
                "binary CFG mutation skipped for "
                + str(operation.get("path", "unknown entrypoint"))
                + ": "
                + str(operation.get("reason", "unspecified"))
            )
            operation_results.append(
                {
                    "operator": operation.get("operator"),
                    "path": operation.get("path"),
                    "status": "skipped",
                    "reason": operation.get("reason", "unspecified"),
                }
            )
        elif operation.get("operator") == "runtime_entrypoint_wrapper":
            wrapper = variant_dir / str(operation.get("path", "run_variant.sh"))
            if not wrapper.exists() or not os.access(wrapper, os.X_OK):
                errors.append("runtime wrapper is missing or not executable")
            else:
                operation_results.append({"operator": operation.get("operator"), "path": str(wrapper.name), "status": "checked"})
        elif operation.get("operator") == "runtime_metadata_overlay":
            overlay = variant_dir / str(operation.get("path", "variant_runtime.json"))
            if not overlay.exists():
                errors.append("runtime metadata overlay is missing")
            else:
                operation_results.append({"operator": operation.get("operator"), "path": str(overlay.name), "status": "checked"})
        else:
            operation_results.append({"operator": operation.get("operator"), "status": "recorded"})

    syntax_results = []
    for operation in manifest.get("operations", []):
        if operation.get("operator") == "opaque_guard_injection":
            syntax_results.append(_syntax_check(variant_dir, operation["path"]))
    build_result = _build_check(
        variant_dir,
        list(manifest.get("seed_metadata", {}).get("declared_files", []) or []),
    ) if build else {"status": "not_requested"}
    if build and build_result.get("status") == "warning":
        warnings.append("Makefile build did not pass; see build result")
    if any(result.get("status") == "warning" for result in syntax_results):
        warnings.append("one or more source syntax checks did not pass")

    substantive_artifact_changed = sum(
        1
        for result in operation_results
        if result.get("operator") in {"compiled_artifact_rebuild", "binary_cfg_mutation"}
        and result.get("status") == "checked"
        and result.get("changed")
    )
    source_changed = sum(
        1
        for result in operation_results
        if result.get("operator") == "opaque_guard_injection" and result.get("status") == "checked"
    )

    return {
        "variant_id": manifest.get("variant_id"),
        "parent_id": manifest.get("parent_id"),
        "category": manifest.get("category"),
        "variant_path": manifest.get("variant_path"),
        "status": "failed" if errors else "passed",
        "errors": errors,
        "warnings": warnings,
        "operations": operation_results,
        "syntax_checks": syntax_results,
        "build": build_result,
        "substantive_artifact_changed": substantive_artifact_changed,
        "source_mutations_checked": source_changed,
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def validate_tree(output_root: Path, build: bool = False) -> Dict[str, Any]:
    manifests = sorted(output_root.rglob("mutation_manifest.json"))
    results = [validate_manifest(path, build=build) for path in manifests]
    passed = sum(result["status"] == "passed" for result in results)
    failed = len(results) - passed
    report = {
        "schema_version": 1,
        "output_root": str(output_root.resolve()),
        "variants": len(results),
        "passed": passed,
        "failed": failed,
        "substantive_artifact_mutations": sum(
            result.get("substantive_artifact_changed", 0) for result in results
        ),
        "source_mutations_checked": sum(result.get("source_mutations_checked", 0) for result in results),
        "status": "passed" if failed == 0 and results else "failed",
        "results": results,
    }
    (output_root / "validation_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return report
