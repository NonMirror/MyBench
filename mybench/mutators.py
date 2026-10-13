from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import shlex
import struct
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .model import Seed


OPAQUE_GUARD_PREFIX = "mybench_opaque_guard_"
DECOY_FUNCTION_PREFIX = "mybench_decoy_function_"
DEAD_CODE_PREFIX = "mybench_dead_code_"
DUPLICATE_STRING_PREFIX = "mybench_duplicate_string_"
IRRELEVANT_SYSCALL_PREFIX = "mybench_irrelevant_syscall_"
SOURCE_NOISE_OPERATORS = (
    "decoy_function_injection",
    "dead_code_injection",
    "duplicate_string_injection",
    "irrelevant_syscall_injection",
)
EXCLUDED_TECHNIQUES = ("control_flow_flattening", "ollvm", "packing", "shell")
SOURCE_NOISE_LIMITS = {
    "max_decoy_functions": 2,
    "max_dead_code_blocks": 2,
    "max_duplicate_strings": 3,
    "max_irrelevant_syscalls": 1,
}
SOURCE_NOISE_LIMIT_MAX = {
    "max_decoy_functions": 32,
    "max_dead_code_blocks": 32,
    "max_duplicate_strings": 64,
    "max_irrelevant_syscalls": 16,
}
DEFAULT_NOISE_POLICY = {
    "enabled_operators": list(SOURCE_NOISE_OPERATORS),
    "excluded_techniques": list(EXCLUDED_TECHNIQUES),
    "limits": dict(SOURCE_NOISE_LIMITS),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_component(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return value or "seed"


def _replace_file(path: Path, content: str, encoding: str = "utf-8") -> None:
    # Variants are hard-linked by default. Unlink before writing so the seed is
    # never modified through a shared inode.
    if path.exists() or path.is_symlink():
        path.unlink()
    path.write_text(content, encoding=encoding)


def _detach_file(path: Path) -> None:
    """Break a hardlink before changing metadata on a copied seed artifact."""
    if not path.is_file() or path.is_symlink():
        return
    temporary = path.with_name(path.name + ".mybench-detach")
    shutil.copy2(path, temporary)
    path.unlink()
    temporary.replace(path)


_SENSITIVE_PARTS = {
    "test_solver", "solution", "soln", "writeup", "golden", "oracle",
}
_SENSITIVE_NAMES = {
    "flag", "flag.txt", "flag.json", "answer", "answer.txt",
    "solve.py", "solver.py", "solution.py", "solve.sh", "solution.sh",
}


def _is_sensitive(relative_path: Path) -> bool:
    parts = {part.lower() for part in relative_path.parts}
    name = relative_path.name.lower()
    if parts & _SENSITIVE_PARTS:
        return True
    if name in _SENSITIVE_NAMES:
        return True
    if name.startswith("flag.") or name.startswith("answer."):
        return True
    return False


def _link_tree(source: Path, destination: Path, removed: Optional[List[str]] = None, relative: Path = Path(".")) -> None:
    if removed is None:
        removed = []
    destination.mkdir(parents=True, exist_ok=False)
    for item in source.iterdir():
        if item.name in {".git", "__pycache__"}:
            continue
        item_relative = Path(item.name) if str(relative) == "." else relative / item.name
        if _is_sensitive(item_relative):
            removed.append(item_relative.as_posix())
            continue
        target = destination / item.name
        if item.is_dir() and not item.is_symlink():
            _link_tree(item, target, removed, item_relative)
        elif item.is_symlink():
            target.symlink_to(os.readlink(item))
        else:
            try:
                os.link(item, target)
            except OSError:
                shutil.copy2(item, target)


def _source_candidate(seed: Seed) -> Optional[Path]:
    return seed.source_files[0] if seed.source_files else None


def _opaque_identifier(variant_id: str) -> str:
    return OPAQUE_GUARD_PREFIX + re.sub(r"[^A-Za-z0-9_]", "_", variant_id)


def _normalize_noise_policy(policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    candidate = copy.deepcopy(DEFAULT_NOISE_POLICY if policy is None else policy)
    if not isinstance(candidate, dict):
        raise ValueError("noise policy must be an object")
    enabled = candidate.get("enabled_operators")
    excluded = candidate.get("excluded_techniques")
    limits = candidate.get("limits", SOURCE_NOISE_LIMITS)
    if not isinstance(enabled, list) or any(not isinstance(item, str) for item in enabled):
        raise ValueError("noise_policy.enabled_operators must be a list of strings")
    if len(set(enabled)) != len(enabled) or any(item not in SOURCE_NOISE_OPERATORS for item in enabled):
        raise ValueError("noise_policy.enabled_operators contains an unknown or duplicate operator")
    if not isinstance(excluded, list) or any(not isinstance(item, str) for item in excluded):
        raise ValueError("noise_policy.excluded_techniques must be a list of strings")
    if len(set(excluded)) != len(excluded) or set(EXCLUDED_TECHNIQUES) - set(excluded):
        raise ValueError("noise policy must exclude control-flow flattening, OLLVM, packing, and shell")
    if any(item not in EXCLUDED_TECHNIQUES for item in excluded):
        raise ValueError("noise_policy.excluded_techniques contains an unknown technique")
    if not isinstance(limits, dict):
        raise ValueError("noise_policy.limits must be an object")
    normalized_limits = dict(SOURCE_NOISE_LIMITS)
    for key, value in limits.items():
        if key not in normalized_limits or isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid noise policy limit: {key}")
        if value < 0 or value > SOURCE_NOISE_LIMIT_MAX[key]:
            raise ValueError(f"noise policy limit is out of range: {key}")
        normalized_limits[key] = value
    return {
        "enabled_operators": list(enabled),
        "excluded_techniques": list(excluded),
        "limits": normalized_limits,
    }


def _noise_identifier(prefix: str, variant_id: str) -> str:
    return prefix + re.sub(r"[^A-Za-z0-9_]", "_", variant_id)


def _noise_language(source: Path) -> str:
    suffix = source.suffix.lower()
    if suffix in {".cc", ".cpp", ".cxx"}:
        return "cpp"
    if suffix in {".c", ".m", ".mm"}:
        return "c"
    return suffix.lstrip(".") or "unknown"


def _c_function_match(content: str) -> Optional[re.Match[str]]:
    return re.search(r"\bmain\s*\([^{};]*\)\s*\{", content) or re.search(
        r"\b[A-Za-z_][\w:\s*<&>,~]*\s+[A-Za-z_]\w*\s*\([^{};]*\)\s*\{", content
    )


def _noise_skip(source: Path, relative_path: Path, operator: str, reason: str) -> Dict[str, Any]:
    digest = sha256_file(source)
    return {
        "operator": operator,
        "strategy": "source_noise_skipped",
        "language": _noise_language(source),
        "path": relative_path.as_posix(),
        "before_sha256": digest,
        "after_sha256": digest,
        "marker": None,
        "changed": False,
        "reason": reason,
    }


def _inject_c_noise(source: Path, relative_path: Path, variant_id: str, operator: str) -> Dict[str, Any]:
    before_hash = sha256_file(source)
    suffix = source.suffix.lower()
    if suffix not in {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}:
        return _noise_skip(source, relative_path, operator, f"source noise supports C/C++ only, got {suffix or '<none>'}")
    try:
        content = source.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return _noise_skip(source, relative_path, operator, "source is not valid UTF-8")
    function_match = _c_function_match(content)
    if function_match is None:
        return _noise_skip(source, relative_path, operator, "no compatible C/C++ function definition found")
    tag = hashlib.sha256((variant_id + ":" + operator).encode()).hexdigest()[:16]
    if operator == "decoy_function_injection":
        marker = _noise_identifier(DECOY_FUNCTION_PREFIX, variant_id)
        helper = f"\n#if defined(__GNUC__) || defined(__clang__)\n__attribute__((noinline, used)) static unsigned long long {marker}(unsigned long long seed) {{\n#else\nstatic unsigned long long {marker}(unsigned long long seed) {{\n#endif\n    volatile unsigned long long state = seed ^ 0x{tag}ULL;\n    return state + 0x{tag}ULL;\n}}\n"
        body = "\n"
        strategy = "noinline_unused_decoy_function"
    elif operator == "dead_code_injection":
        marker = _noise_identifier(DEAD_CODE_PREFIX, variant_id)
        helper = f"\n#if defined(__GNUC__) || defined(__clang__)\n__attribute__((noinline, used)) static int {marker}(void) {{\n#else\nstatic int {marker}(void) {{\n#endif\n    volatile unsigned long long state = 0x{tag}ULL;\n    return (state ^ 0x{tag}ULL) == 1ULL;\n}}\n"
        body = f"\n    if ({marker}()) {{\n        volatile unsigned long long mybench_dead_sink = 0x{tag}ULL;\n        mybench_dead_sink ^= 0x{tag}ULL;\n        (void)mybench_dead_sink;\n    }}\n"
        strategy = "volatile_false_branch"
    elif operator == "duplicate_string_injection":
        marker = _noise_identifier(DUPLICATE_STRING_PREFIX, variant_id)
        a, b = marker + "_a", marker + "_b"
        helper = f'\nstatic volatile const char {a}[] = "mybench decoy diagnostic {tag}";\nstatic volatile const char {b}[] = "mybench decoy diagnostic {tag}";\n#if defined(__GNUC__) || defined(__clang__)\n__attribute__((noinline, used)) static unsigned long long {marker}(void) {{\n#else\nstatic unsigned long long {marker}(void) {{\n#endif\n    return (unsigned char){a}[0] ^ (unsigned char){b}[0];\n}}\n'
        body = f"\n    {{\n        volatile unsigned long long mybench_duplicate_sink = {marker}();\n        (void)mybench_duplicate_sink;\n    }}\n"
        strategy = "volatile_duplicate_literals"
    elif operator == "irrelevant_syscall_injection":
        marker = _noise_identifier(IRRELEVANT_SYSCALL_PREFIX, variant_id)
        helper = f"\n#if defined(__unix__) || defined(__APPLE__)\n#include <unistd.h>\n#endif\n#if defined(__GNUC__) || defined(__clang__)\n__attribute__((noinline, used)) static long {marker}(void) {{\n#else\nstatic long {marker}(void) {{\n#endif\n#if defined(__unix__) || defined(__APPLE__)\n    return (long)getpid();\n#else\n    return 0L;\n#endif\n}}\n"
        body = f"\n    {{\n        volatile unsigned long long mybench_syscall_gate = 0x{tag}ULL;\n        if ((mybench_syscall_gate ^ 0x{tag}ULL) == 1ULL) {{\n            volatile long mybench_syscall_sink = {marker}();\n            (void)mybench_syscall_sink;\n        }}\n    }}\n"
        strategy = "guarded_getpid_read_only"
    else:
        raise ValueError(f"unknown source noise operator: {operator}")
    insert_at = function_match.end()
    _replace_file(source, helper + content[:insert_at] + body + content[insert_at:])
    return {
        "operator": operator,
        "strategy": strategy,
        "language": _noise_language(source),
        "path": relative_path.as_posix(),
        "before_sha256": before_hash,
        "after_sha256": sha256_file(source),
        "marker": marker,
        "changed": before_hash != sha256_file(source),
    }


def _mutate_source_noise(source: Path, relative_path: Path, variant_id: str,
                         enabled_operators: Optional[Iterable[str]] = None,
                         limits: Optional[Dict[str, int]] = None) -> List[Dict[str, Any]]:
    enabled = set(SOURCE_NOISE_OPERATORS if enabled_operators is None else enabled_operators)
    limit_keys = {
        "decoy_function_injection": "max_decoy_functions",
        "dead_code_injection": "max_dead_code_blocks",
        "duplicate_string_injection": "max_duplicate_strings",
        "irrelevant_syscall_injection": "max_irrelevant_syscalls",
    }
    results = []
    for operator in SOURCE_NOISE_OPERATORS:
        if operator not in enabled:
            continue
        key = limit_keys[operator]
        if limits is not None and limits.get(key, 0) <= 0:
            results.append(_noise_skip(source, relative_path, operator, f"operator disabled by policy limit {key}=0"))
        else:
            results.append(_inject_c_noise(source, relative_path, variant_id, operator))
    return results


def _mutate_source(source: Path, relative_path: Path, variant_id: str) -> Dict[str, Any]:
    before_hash = sha256_file(source)
    try:
        content = source.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return {
            "operator": "source_mutation_skipped",
            "path": relative_path.as_posix(),
            "reason": "source is not valid UTF-8",
            "before_sha256": before_hash,
            "after_sha256": before_hash,
            "changed": False,
        }

    ident = _opaque_identifier(variant_id)
    tag = hashlib.sha256(variant_id.encode("utf-8")).hexdigest()[:16]
    suffix = source.suffix.lower()
    if suffix in {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}:
        main_match = re.search(r"\bmain\s*\([^{};]*\)\s*\{", content)
        function_match = main_match or re.search(
            r"\b[A-Za-z_][\w:\s*<&>,~]*\s+[A-Za-z_]\w*\s*\([^{};]*\)\s*\{",
            content,
        )
        if function_match is None:
            return {
                "operator": "source_mutation_skipped",
                "path": relative_path.as_posix(),
                "reason": "no compatible C/C++ function definition found",
                "before_sha256": before_hash,
                "after_sha256": before_hash,
                "changed": False,
            }
        # The volatile read prevents the compiler from proving the predicate
        # false. The value is initialized to the same deterministic constant,
        # so the branch is false for normal execution while still adding a
        # real call and CFG edge to the compiled challenge.
        guard_function = (
            f"\n#if defined(__GNUC__) || defined(__clang__)\n"
            f"__attribute__((noinline)) static int {ident}(void) {{\n"
            f"#else\n"
            f"static int {ident}(void) {{\n"
            f"#endif\n"
            f"    volatile unsigned long long value = 0x{tag}ULL;\n"
            f"    return ((value ^ 0x{tag}ULL) == 1ULL);\n"
            f"}}\n"
        )
        branch = (
            f"\n    if ({ident}()) {{\n"
            f"        volatile unsigned long long mybench_guard_sink = 0ULL;\n"
            f"        (void)mybench_guard_sink;\n"
            f"    }}\n"
        )
        insert_at = function_match.end()
        mutated = content[:insert_at] + branch + content[insert_at:]
        mutated = guard_function + mutated
        strategy = "opaque_guard_injection"
    elif suffix in {".py"}:
        mutated = content + (
            f"\n\ndef {ident}():\n"
            f"    value = int('{tag}', 16)\n"
            f"    return (value ^ value) == 1\n\n"
            f"if {ident}():\n"
            f"    _mybench_guard_sink = 0\n"
            f"    del _mybench_guard_sink\n"
        )
        strategy = "opaque_guard_injection"
    elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
        mutated = content + (
            f"\n\nfunction {ident}() {{\n"
            f"  const value = 0x{tag};\n"
            f"  return ((value ^ value) === 1);\n"
            f"}}\n\n"
            f"if ({ident}()) {{\n"
            f"  const mybenchGuardSink = 0;\n"
            f"  void mybenchGuardSink;\n"
            f"}}\n"
        )
        strategy = "opaque_guard_injection"
    elif suffix == ".go":
        mutated = content + (
            f"\n\nfunc {ident}() bool {{\n"
            f"\tvar value uint64 = 0x{tag}\n"
            f"\treturn (value ^ value) == 1\n"
            f"}}\n\n"
            f"func init() {{\n"
            f"\tif {ident}() {{\n"
            f"\t\tvar mybenchGuardSink uint64\n"
            f"\t\t_ = mybenchGuardSink\n"
            f"\t}}\n"
            f"}}\n"
        )
        strategy = "opaque_guard_injection"
    else:
        return {
            "operator": "source_mutation_skipped",
            "path": relative_path.as_posix(),
            "reason": f"unsupported source suffix: {suffix or '<none>'}",
            "before_sha256": before_hash,
            "after_sha256": before_hash,
            "changed": False,
        }

    _replace_file(source, mutated)
    after_hash = sha256_file(source)
    return {
        "operator": "opaque_guard_injection",
        "strategy": strategy,
        "path": relative_path.as_posix(),
        "before_sha256": before_hash,
        "after_sha256": after_hash,
        "marker": ident,
        "changed": before_hash != after_hash,
    }


def _matching_compiled_target(seed: Seed, source: Path, variant_dir: Path) -> Optional[tuple[Path, Path]]:
    """Find a shipped executable whose basename matches the mutated source."""
    target = source.with_suffix("")
    if not target.exists() or not target.is_file() or not _probable_entrypoint(target):
        return None
    relative = target.relative_to(seed.seed_path)
    copied = variant_dir / relative
    if not copied.exists() or copied.is_symlink():
        return None
    return target, copied


def _compatible_binary_format(reference: Path, candidate: Path) -> bool:
    """Require the rebuilt artifact to keep the seed's executable family/arch."""
    reference_description = _file_description(reference)
    candidate_description = _file_description(candidate)
    if not reference_description or not candidate_description:
        return False
    families = ("elf", "mach-o", "pe32")
    family = next((item for item in families if item in reference_description), None)
    if family is None or family not in candidate_description:
        return False
    architecture_tokens = (
        "x86-64", "x86_64", "i386", "i686", "arm64", "aarch64", "arm",
        "powerpc", "ppc64", "mips", "risc-v", "riscv",
    )
    reference_arch = next((item for item in architecture_tokens if item in reference_description), None)
    return reference_arch is not None and reference_arch in candidate_description


def _cfg_witness(path: Path, function: Any = "main") -> Optional[Dict[str, int]]:
    """Return a small normalized CFG witness when radare2 is available."""
    r2 = shutil.which("r2")
    if not r2:
        return None
    try:
        result = subprocess.run(
            [r2, "-q", "-c", f"aa; afbj @ {function}; q", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    payload = None
    for line in result.stdout.splitlines():
        candidate = line.strip()
        if candidate.startswith("[") and candidate.endswith("]"):
            try:
                payload = json.loads(candidate)
            except json.JSONDecodeError:
                continue
    if not isinstance(payload, list) or not payload:
        return None
    edges = 0
    instructions = 0
    for block in payload:
        if not isinstance(block, dict):
            continue
        instructions += int(block.get("ninstr", 0) or 0)
        for key in ("jump", "fail"):
            value = block.get(key)
            if isinstance(value, int) and value != 18446744073709551615:
                edges += 1
    return {"blocks": len(payload), "instructions": instructions, "edges": edges}


def _r2_function_ops_candidates(path: Path) -> List[Dict[str, Any]]:
    """Analyze known functions in one r2 session and return their op lists.

    Some stripped challenge binaries put all conditional control flow in a
    helper rather than in `main`. Keeping this as one r2 invocation avoids the
    quadratic process overhead of opening the binary once per function.
    """
    r2 = shutil.which("r2")
    if not r2:
        return []
    try:
        inventory = subprocess.run(
            [r2, "-q", "-c", "aa; aflj; q", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    functions: List[Dict[str, Any]] = []
    for line in inventory.stdout.splitlines():
        candidate = line.strip()
        if not candidate.startswith("[") or not candidate.endswith("]"):
            continue
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, list):
            functions = [
                item for item in payload
                if isinstance(item, dict) and isinstance(item.get("addr"), int)
                and not str(item.get("name", "")).startswith("sym.imp.")
            ]
            break
    if not functions:
        return []
    # Prefer user-code names and entrypoint-like functions. The cap protects
    # generation from pathological statically linked libraries while still
    # covering ordinary stripped CTF binaries.
    functions.sort(key=lambda item: (
        0 if str(item.get("name", "")) in {"main", "sym.main", "entry0"} else 1,
        0 if str(item.get("name", "")).startswith(("sym.", "fcn.")) else 1,
        int(item.get("addr", 0)),
    ))
    functions = functions[:256]
    commands = ["aa"] + [f"pdfj @ {int(item['addr'])}" for item in functions] + ["q"]
    try:
        result = subprocess.run(
            [r2, "-q", "-c", "; ".join(commands), str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    parsed: List[Dict[str, Any]] = []
    for line in result.stdout.splitlines():
        candidate = line.strip()
        if not candidate.startswith("{") or not candidate.endswith("}"):
            continue
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("ops"), list):
            parsed.append(payload)
    return parsed


def _r2_function_ops(path: Path) -> Optional[Dict[str, Any]]:
    """Return a radare2 function JSON object for main, or entry0 as fallback."""
    r2 = shutil.which("r2")
    if not r2:
        return None
    for function in ("main", "entry0"):
        try:
            result = subprocess.run(
                [r2, "-q", "-c", f"aa; pdfj @ {function}; q", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        for line in result.stdout.splitlines():
            candidate = line.strip()
            if not candidate.startswith("{") or not candidate.endswith("}"):
                continue
            try:
                payload = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and isinstance(payload.get("ops"), list):
                return payload
    return None


def _unconditional_branch_bytes(op: Dict[str, Any]) -> Optional[bytes]:
    """Turn one x86/AArch64 conditional branch into an unconditional branch."""
    raw = bytes.fromhex(str(op.get("bytes", "")))
    address = int(op.get("addr", op.get("offset", 0)))
    target = op.get("jump")
    if not raw or not isinstance(target, int):
        return None
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7F:
        displacement = target - (address + 2)
        if -128 <= displacement <= 127:
            return bytes([0xEB, displacement & 0xFF])
    if len(raw) >= 6 and raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F:
        displacement = target - (address + 5)
        if -(1 << 31) <= displacement < (1 << 31):
            return bytes([0xE9]) + struct.pack("<i", displacement) + b"\x90"
    if len(raw) == 4:
        word = int.from_bytes(raw, "little")
        if word & 0xFF000010 == 0x54000000:
            displacement = target - address
            if displacement % 4 == 0 and -(1 << 27) <= displacement < (1 << 27):
                immediate = (displacement >> 2) & 0x03FFFFFF
                return (0x14000000 | immediate).to_bytes(4, "little")
    return None


def _mutate_binary_cfg(variant_dir: Path, seed: Seed, entrypoint: str) -> Dict[str, Any]:
    """Patch one real conditional branch when source rebuild is unavailable."""
    target = variant_dir / entrypoint
    original = seed.seed_path / entrypoint
    description = _file_description(original)
    if not any(family in description for family in ("elf", "mach-o", "pe32")):
        return {
            "operator": "binary_cfg_mutation_skipped",
            "path": entrypoint,
            "reason": "entrypoint is not a supported native binary",
            "changed": False,
        }
    function = _r2_function_ops(original)
    if function is None:
        return {
            "operator": "binary_cfg_mutation_skipped",
            "path": entrypoint,
            "reason": "radare2 could not analyze main/entry0",
            "changed": False,
        }
    branch = next((op for op in function.get("ops", []) if op.get("type") == "cjmp"), None)
    if branch is None:
        for candidate in _r2_function_ops_candidates(original):
            candidate_branch = next((op for op in candidate.get("ops", []) if op.get("type") == "cjmp"), None)
            if candidate_branch is not None:
                function = candidate
                branch = candidate_branch
                break
    if branch is None:
        return {
            "operator": "binary_cfg_mutation_skipped",
            "path": entrypoint,
            "reason": "no conditional branch found in analyzed user functions",
            "changed": False,
        }
    before_bytes = bytes.fromhex(str(branch.get("bytes", "")))
    after_bytes = _unconditional_branch_bytes(branch)
    if after_bytes is None or len(after_bytes) != len(before_bytes):
        return {
            "operator": "binary_cfg_mutation_skipped",
            "path": entrypoint,
            "reason": "conditional branch encoding is not patchable without changing instruction size",
            "changed": False,
        }
    _detach_file(target)
    address = int(branch.get("addr", branch.get("offset", 0)))
    r2 = shutil.which("r2")
    try:
        result = subprocess.run(
            [r2, "-q", "-w", "-c", f"wx {after_bytes.hex()} @ {address}; q", str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        shutil.copy2(original, target)
        return {
            "operator": "binary_cfg_mutation_skipped",
            "path": entrypoint,
            "reason": f"binary patch failed: {exc}",
            "changed": False,
        }
    if result.returncode != 0 or sha256_file(target) == sha256_file(original):
        shutil.copy2(original, target)
        return {
            "operator": "binary_cfg_mutation_skipped",
            "path": entrypoint,
            "reason": f"binary patch command returned {result.returncode}",
            "changed": False,
        }
    function_addr = int(function.get("addr", function.get("offset", address)))
    cfg_before = _cfg_witness(original, function_addr)
    cfg_after = _cfg_witness(target, function_addr)
    if cfg_before is not None and cfg_after is not None and cfg_before == cfg_after:
        shutil.copy2(original, target)
        return {
            "operator": "binary_cfg_mutation_skipped",
            "path": entrypoint,
            "reason": f"CFG witness did not change ({cfg_before})",
            "changed": False,
        }
    return {
        "operator": "binary_cfg_mutation",
        "path": entrypoint,
        "function": function.get("name"),
        "function_addr": function_addr,
        "address": address,
        "before_bytes": before_bytes.hex(),
        "after_bytes": after_bytes.hex(),
        "before_sha256": sha256_file(original),
        "after_sha256": sha256_file(target),
        "cfg_before": cfg_before,
        "cfg_after": cfg_after,
        "cfg_changed": cfg_before is not None and cfg_after is not None and cfg_before != cfg_after,
        "changed": True,
    }


def _rebuild_compiled_artifact(
    variant_dir: Path,
    seed: Seed,
    source_operation: Dict[str, Any],
) -> Dict[str, Any]:
    """Recompile a shipped source/binary pair so the mutation reaches the artifact.

    CTFbench often ships both a source file and the executable actually used by
    the challenge. Mutating only the source leaves the deployed CFG unchanged;
    this operator makes the relationship explicit and replaces the copied
    executable only after a successful, detached compilation.
    """
    source_rel = source_operation.get("path")
    if not source_rel:
        return {
            "operator": "compiled_artifact_rebuild_skipped",
            "reason": "source operation has no path",
            "changed": False,
        }
    source_seed_path = seed.seed_path / str(source_rel)
    source_declared = source_seed_path in seed.declared_files
    source = variant_dir / str(source_rel)
    suffix = source.suffix.lower()
    if suffix not in {".c", ".cc", ".cpp", ".cxx"}:
        return {
            "operator": "compiled_artifact_rebuild_skipped",
            "source": str(source_rel),
            "required": not source_declared,
            "reason": f"automatic rebuild supports C/C++ only, got {suffix or '<none>'}",
            "changed": False,
        }
    match = _matching_compiled_target(seed, seed.seed_path / str(source_rel), variant_dir)
    if match is None:
        return {
            "operator": "compiled_artifact_rebuild_skipped",
            "source": str(source_rel),
            "required": not source_declared,
            "reason": "no shipped executable with the source basename",
            "changed": False,
        }
    original_target, target = match
    before_hash = sha256_file(target)
    cfg_before = _cfg_witness(original_target)
    temporary = target.with_name(target.name + ".mybench-build")
    include_dirs = sorted({str(path.parent) for path in variant_dir.rglob("*") if path.is_dir()})
    source_rel_in_variant = source.relative_to(variant_dir).as_posix()
    target_rel_in_variant = temporary.relative_to(variant_dir).as_posix()
    attempts: List[tuple[str, List[str], Path]] = []
    compiler = shutil.which("g++" if suffix in {".cc", ".cpp", ".cxx"} else "gcc")
    language_standard = "c++11" if suffix in {".cc", ".cpp", ".cxx"} else "gnu11"
    if compiler:
        command = [compiler, f"-std={language_standard}", "-O0", "-g0", "-fno-omit-frame-pointer"]
        command.extend(f"-I{path}" for path in include_dirs[:80])
        command.extend([str(source), "-o", str(temporary)])
        attempts.append((compiler, command, variant_dir))

    docker = shutil.which("docker")
    docker_image = os.environ.get("MYBENCH_BUILD_IMAGE", "gcc:12-bookworm")
    docker_available = False
    if docker:
        try:
            image_check = subprocess.run(
                [docker, "image", "inspect", docker_image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            docker_available = image_check.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            docker_available = False
    if docker_available:
        container_source = "/src/" + source_rel_in_variant
        container_target = "/src/" + target_rel_in_variant
        container_includes = ["-I/src/" + path.relative_to(variant_dir).as_posix() for path in variant_dir.rglob("*") if path.is_dir()]
        docker_command = [
            docker, "run", "--rm", "--platform", "linux/amd64",
            "-v", f"{variant_dir}:/src",
            docker_image,
            "g++" if suffix in {".cc", ".cpp", ".cxx"} else "gcc",
            f"-std={language_standard}", "-O0", "-g0", "-fno-omit-frame-pointer", "-static",
        ]
        docker_command.extend(container_includes[:80])
        docker_command.extend([container_source, "-o", container_target])
        attempts.append((f"docker:{docker_image}", docker_command, variant_dir))
        dynamic_docker_command = list(docker_command)
        dynamic_docker_command.remove("-static")
        attempts.append((f"docker:{docker_image}:dynamic", dynamic_docker_command, variant_dir))

    failures: List[str] = []
    selected_tool = None
    selected_command: Optional[List[str]] = None
    selected_output = ""
    selected_cfg_after: Optional[Dict[str, int]] = None
    for tool_name, command, cwd in attempts:
        if temporary.exists():
            temporary.unlink()
        try:
            result = subprocess.run(
                command,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=180,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            failures.append(f"{tool_name}: {exc}")
            continue
        if result.returncode != 0 or not temporary.exists():
            failures.append(f"{tool_name}: compiler returned {result.returncode}: {result.stdout[-500:]}")
            continue
        if not _compatible_binary_format(original_target, temporary):
            failures.append(
                f"{tool_name}: output format does not match seed "
                f"({_file_description(original_target)} vs {_file_description(temporary)})"
            )
            temporary.unlink()
            continue
        cfg_after = _cfg_witness(temporary)
        if cfg_before is not None and cfg_after is not None and cfg_before == cfg_after:
            failures.append(f"{tool_name}: CFG witness did not change ({cfg_before})")
            temporary.unlink()
            continue
        selected_tool = tool_name
        selected_command = command
        selected_output = result.stdout[-2000:]
        selected_cfg_after = cfg_after
        break

    if selected_tool is None:
        if temporary.exists():
            temporary.unlink()
        return {
            "operator": "compiled_artifact_rebuild_skipped",
            "source": str(source_rel),
            "path": target.relative_to(variant_dir).as_posix(),
            "required": True,
            "reason": "; ".join(failures) if failures else "no compatible compiler available",
            "changed": False,
        }

    temporary.chmod(target.stat().st_mode | 0o111)
    target.unlink()
    temporary.replace(target)
    after_hash = sha256_file(target)
    return {
        "operator": "compiled_artifact_rebuild",
        "source": str(source_rel),
        "path": target.relative_to(variant_dir).as_posix(),
        "marker": source_operation.get("marker"),
        "compiler": selected_tool,
        "command": selected_command,
        "output": selected_output,
        "before_sha256": before_hash,
        "after_sha256": after_hash,
        "changed": before_hash != after_hash,
        "source_seed_sha256": sha256_file(seed.seed_path / str(source_rel)),
        "seed_artifact_sha256": sha256_file(original_target),
        "cfg_before": cfg_before,
        "cfg_after": selected_cfg_after,
        "cfg_changed": cfg_before is not None and selected_cfg_after is not None and cfg_before != selected_cfg_after,
    }


def _file_description(path: Path) -> str:
    file_tool = shutil.which("file")
    if not file_tool:
        return ""
    try:
        result = subprocess.run([file_tool, "-b", str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5)
        return result.stdout.lower()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _probable_entrypoint(path: Path) -> bool:
    rel = "/".join(part.lower() for part in path.parts)
    name = path.name.lower()
    if any(token in rel for token in ("solver", "solve", "solution", "test_solver", "poc", "exploit")):
        return False
    if name.endswith((".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".so", ".c", ".cc", ".cpp", ".h", ".py")):
        # Python is accepted below only when it has a shebang and is not a solver.
        if not name.endswith(".py"):
            return False
    try:
        prefix = path.read_bytes()[:128]
    except OSError:
        return False
    description = _file_description(path)
    if "elf" in description or "mach-o" in description or "pe32" in description or "executable" in description:
        return True
    return prefix.startswith(b"#!")


def _native_artifact_candidate(seed: Seed, variant_dir: Path) -> Optional[str]:
    """Find a shipped native artifact when no runnable wrapper entrypoint exists."""
    candidates = list(seed.declared_files)
    candidates.extend(p for p in seed.seed_path.rglob("*") if p.is_file() and p not in candidates)
    for candidate in candidates:
        relative = candidate.relative_to(seed.seed_path)
        if _is_sensitive(relative):
            continue
        copied = variant_dir / relative
        if not copied.exists() or copied.is_symlink():
            continue
        if any(token in "/".join(relative.parts).lower() for token in ("solver", "solution", "writeup", "exploit")):
            continue
        description = _file_description(candidate)
        if any(family in description for family in ("elf", "mach-o", "pe32")):
            return relative.as_posix()
    return None


def _write_runtime_wrapper(variant_dir: Path, seed: Seed, variant_id: str) -> Dict[str, Any]:
    entry_path = None
    candidates = list(seed.declared_files)
    candidates.extend(p for p in seed.seed_path.iterdir() if p.is_file() and p not in candidates)
    for candidate in candidates:
        relative = candidate.relative_to(seed.seed_path)
        copied = variant_dir / relative
        if copied.exists() and _probable_entrypoint(candidate):
            entry_path = relative.as_posix()
            break
    if entry_path is None:
        overlay = variant_dir / "variant_runtime.json"
        _replace_file(
            overlay,
            json.dumps(
                {
                    "variant_id": variant_id,
                    "parent_id": seed.dataset_key,
                    "environment": {
                        "MYBENCH_VARIANT_ID": variant_id,
                        "MYBENCH_PARENT_SEED": seed.dataset_key,
                    },
                    "entrypoint": None,
                    "reason": "no safe ELF or shebang entrypoint detected",
                },
                indent=2,
            ) + "\n",
        )
        return {
            "operator": "runtime_metadata_overlay",
            "path": "variant_runtime.json",
            "entrypoint": None,
            "changed": True,
        }

    copied_entry = variant_dir / entry_path
    _detach_file(copied_entry)
    copied_entry.chmod(copied_entry.stat().st_mode | 0o111)
    wrapper = variant_dir / "run_variant.sh"
    quoted_entry = '"$SCRIPT_DIR/' + entry_path.replace('"', '\\"') + '"'
    content = (
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "SCRIPT_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n"
        f"export MYBENCH_VARIANT_ID={shlex.quote(variant_id)}\n"
        f"export MYBENCH_PARENT_SEED={shlex.quote(seed.dataset_key)}\n"
        f"exec {quoted_entry} \"$@\"\n"
    )
    _replace_file(wrapper, content)
    wrapper.chmod(0o755)
    return {
        "operator": "runtime_entrypoint_wrapper",
        "path": "run_variant.sh",
        "entrypoint": entry_path,
        "changed": True,
    }


def _sanitize_challenge_json(
    variant_dir: Path,
    seed: Seed,
    variant_id: str,
    operations: List[Dict[str, Any]],
    removed_sensitive: List[str],
) -> None:
    public = copy.deepcopy(seed.metadata)
    for secret_key in ("flag", "answer", "solution", "secret", "key"):
        public.pop(secret_key, None)
    public["mybench_variant"] = {
        "variant_id": variant_id,
        "parent_id": seed.dataset_key,
        "operations": [op.get("operator") for op in operations],
        "removed_sensitive_files": removed_sensitive,
    }
    if isinstance(public.get("files"), list):
        public["files"] = [rel for rel in public["files"] if rel not in removed_sensitive and (variant_dir / rel).exists()]
    _replace_file(variant_dir / "challenge.json", json.dumps(public, indent=2, ensure_ascii=False) + "\n")


def create_variant(
    seed: Seed,
    output_root: Path,
    ordinal: int = 1,
    noise_policy: Optional[Dict[str, Any]] = None,
) -> Path:
    """Materialize one deterministic variant for every supported seed."""

    normalized_noise_policy = _normalize_noise_policy(noise_policy)
    variant_id = f"{seed.dataset_key}__v{ordinal:02d}"
    relative_parent = Path(seed.category) / seed.split
    variant_dir = output_root / "variants" / relative_parent / _safe_component(variant_id)
    if variant_dir.exists():
        shutil.rmtree(variant_dir)
    removed_sensitive: List[str] = []
    _link_tree(seed.seed_path, variant_dir, removed_sensitive)

    operations: List[Dict[str, Any]] = []
    pending_source_rollback: Optional[tuple[Path, Path, Dict[str, Any]]] = None
    source = _source_candidate(seed)
    if source is not None:
        relative_source = source.relative_to(seed.seed_path)
        copied_source = variant_dir / relative_source
        source_operation = _mutate_source(copied_source, relative_source, variant_id)
        operations.append(source_operation)
        operations.extend(
            _mutate_source_noise(
                copied_source,
                relative_source,
                variant_id,
                normalized_noise_policy["enabled_operators"],
                normalized_noise_policy["limits"],
            )
        )
        if source_operation.get("operator") == "opaque_guard_injection":
            rebuild_operation = _rebuild_compiled_artifact(variant_dir, seed, source_operation)
            operations.append(rebuild_operation)
            if rebuild_operation.get("operator") == "compiled_artifact_rebuild_skipped" and rebuild_operation.get("required"):
                pending_source_rollback = (copied_source, seed.seed_path / relative_source, source_operation)
    else:
        operations.append(
            {
                "operator": "source_mutation_skipped",
                "path": None,
                "reason": "no eligible source file discovered",
                "changed": False,
            }
        )
    runtime_operation = _write_runtime_wrapper(variant_dir, seed, variant_id)
    operations.append(runtime_operation)
    if pending_source_rollback is not None:
        copied_source, seed_source, source_operation = pending_source_rollback
        # An undeclared source is retained only when the generated entrypoint
        # is that source itself. In that case it is the deployed runtime input
        # (for example an executable Python/Go script); otherwise the binary or
        # launcher is the runtime artifact and source-only mutation would be
        # misleading.
        if runtime_operation.get("entrypoint") != relative_source.as_posix():
            copied_source.unlink()
            shutil.copy2(seed_source, copied_source)
            source_operation.update(
                {
                    "operator": "source_mutation_skipped",
                    "reason": "compatible executable rebuild failed: " + str(
                        operations[-2].get("reason", "unspecified")
                    ),
                    "after_sha256": source_operation.get("before_sha256"),
                    "changed": False,
                }
            )
            restored_hash = sha256_file(copied_source)
            for noise_operation in operations:
                if (
                    noise_operation.get("operator") in SOURCE_NOISE_OPERATORS
                    and noise_operation.get("path") == relative_source.as_posix()
                ):
                    noise_operation.update(
                        {
                            "strategy": "source_noise_skipped",
                            "before_sha256": restored_hash,
                            "after_sha256": restored_hash,
                            "marker": None,
                            "changed": False,
                            "reason": "compatible executable rebuild failed; source restored",
                        }
                    )
    # When no compatible source rebuild reached the deployed artifact, try a
    # deterministic in-place CFG mutation on the actual native entrypoint.
    # This is deliberately a separate operator: a wrapper or source edit is
    # never reported as a binary mutation. If the branch cannot be patched,
    # the manifest records an explicit skip with the reason.
    fallback_entrypoint = runtime_operation.get("entrypoint") or _native_artifact_candidate(seed, variant_dir)
    if fallback_entrypoint and not any(
        operation.get("operator") == "compiled_artifact_rebuild" for operation in operations
    ):
        operations.append(_mutate_binary_cfg(variant_dir, seed, str(fallback_entrypoint)))

    _sanitize_challenge_json(variant_dir, seed, variant_id, operations, removed_sensitive)
    public_declared = [
        p.relative_to(seed.seed_path).as_posix()
        for p in seed.declared_files
        if p.relative_to(seed.seed_path).as_posix() not in removed_sensitive
    ]
    manifest = {
        "schema_version": 1,
        "variant_id": variant_id,
        "parent_id": seed.dataset_key,
        "split": seed.split,
        "category": seed.category,
        "seed_path": seed.relative_seed_path,
        "variant_path": variant_dir.relative_to(output_root).as_posix(),
        "noise_policy": normalized_noise_policy,
        "seed_metadata": {
            "name": seed.metadata.get("name"),
            "points": seed.metadata.get("points"),
            "declared_files": public_declared,
            "solver_files": [p.relative_to(seed.seed_path).as_posix() for p in seed.solver_files],
            "flag_sha256": hashlib.sha256(str(seed.metadata.get("flag", "")).encode("utf-8")).hexdigest()
            if "flag" in seed.metadata else None,
        },
        "operations": operations,
        "mutation_status": {
            "source_changed": any(
                operation.get("operator") == "opaque_guard_injection" and operation.get("changed")
                for operation in operations
            ),
            "compiled_artifact_changed": any(
                operation.get("operator") == "compiled_artifact_rebuild" and operation.get("changed")
                for operation in operations
            ),
            "binary_cfg_changed": any(
                operation.get("operator") == "binary_cfg_mutation" and operation.get("changed")
                for operation in operations
            ),
            "substantive_artifact_changed": any(
                operation.get("operator") in {"compiled_artifact_rebuild", "binary_cfg_mutation"}
                and operation.get("changed")
                for operation in operations
            ),
        },
        "build_hints": {
            "has_makefile": seed.has_makefile,
            "has_dockerfile": seed.has_dockerfile,
            "declared_files": public_declared,
        },
        "sanitization": {
            "removed_sensitive_files": sorted(removed_sensitive),
            "source_literals_are_not_redacted": True,
            "archive_contents_are_not_unpacked_or_redacted": True,
        },
        "reproducibility": {
            "rng_seed": int.from_bytes(hashlib.sha256(variant_id.encode()).digest()[:8], "big"),
            "source_mutation_is_deterministic": True,
            "copy_mode": "hardlink_with_copy_on_write",
        },
    }
    _replace_file(variant_dir / "mutation_manifest.json", json.dumps(manifest, indent=2) + "\n")
    operation_lines = []
    for operation in operations:
        description = f"- `{operation.get('operator')}`"
        if operation.get("path"):
            description += f" on `{operation['path']}`"
        if operation.get("reason"):
            description += f": {operation['reason']}"
        operation_lines.append(description)
    (variant_dir / "MUTATION.md").write_text(
        "# MyBench generated variant\n\n"
        f"- variant: `{variant_id}`\n"
        f"- parent: `{seed.dataset_key}`\n"
        f"- category: `{seed.category}`\n\n"
        "This directory was produced automatically. The public challenge metadata is sanitized.\n\n"
        "Operations:\n" + "\n".join(operation_lines) + "\n\n"
        "The mutation manifest records reproducibility metadata and content hashes.\n",
        encoding="utf-8",
    )
    return variant_dir


def generate(
    seeds: Iterable[Seed],
    output_root: Path,
    variants_per_seed: int = 1,
    noise_policy: Optional[Dict[str, Any]] = None,
) -> List[Path]:
    output_root.mkdir(parents=True, exist_ok=True)
    normalized_noise_policy = _normalize_noise_policy(noise_policy)
    created: List[Path] = []
    for seed in seeds:
        for ordinal in range(1, variants_per_seed + 1):
            created.append(create_variant(seed, output_root, ordinal, normalized_noise_policy))
    return created
