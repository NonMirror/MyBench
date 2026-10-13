"""Explicit project build plans for language-aware MyBench rebuilds.

The regular mutator compiler path intentionally builds one source file at a time.
Some seeds describe a real project instead: Cargo selects a Rust binary from
``src/main.rs`` and a Dockerfile may explicitly list all Go files.  This module
turns only those explicit declarations into build plans.  It never guesses a
project from a unique executable or from a source basename.
"""
from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class ProjectBuildPlan:
    """A reproducible, explicitly declared project build.

    ``project_root`` is the source tree containing the declaration.  The
    command is rendered against a detached temporary copy by
    :func:`execute_project_build`, so Cargo or Go cannot write into a seed or
    a hard-linked variant file.
    """

    language: str
    kind: str
    project_root: Path
    source_files: Tuple[Path, ...]
    artifact_name: str
    command: Tuple[str, ...]
    manifest: Optional[Path] = None
    declaration: Optional[Path] = None

    @property
    def source_paths(self) -> Tuple[Path, ...]:
        """Source paths relative to ``project_root``."""
        return self.source_files


@dataclass(frozen=True)
class ProjectBuildResult:
    """Outcome of a detached project build."""

    changed: bool
    artifact: Optional[Path]
    command: Tuple[str, ...]
    stdout: str = ""
    reason: Optional[str] = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _toml_section(text: str, header: str, next_header: str) -> str:
    match = re.search(
        rf"(?ms)^\s*{re.escape(header)}\s*$([\s\S]*?)(?=^\s*(?:\[|\Z))",
        text,
    )
    return match.group(1) if match else ""


def _toml_string(section: str, key: str) -> Optional[str]:
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*([\"'])(.*?)\1\s*(?:#.*)?$", section)
    return match.group(2) if match else None


def _cargo_bin_sections(text: str) -> Iterable[str]:
    # Cargo permits repeated [[bin]] tables.  Restrict each match to the next
    # table header so a later package setting cannot leak into this one.
    for match in re.finditer(r"(?ms)^\s*\[\[bin\]\]\s*$([\s\S]*?)(?=^\s*(?:\[|\Z))", text):
        yield match.group(1)


def _cargo_binary_name(manifest: Path, source_rel: Path) -> Optional[str]:
    try:
        text = manifest.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    package = _toml_string(_toml_section(text, "[package]", ""), "name")
    for section in _cargo_bin_sections(text):
        name = _toml_string(section, "name")
        path = _toml_string(section, "path")
        if name and path and Path(path).as_posix() == source_rel.as_posix():
            return name
    # Cargo's implicit binary is src/main.rs and inherits package.name.
    if source_rel.as_posix() == "src/main.rs":
        return package
    return None


def _nearest_manifest(source: Path) -> Optional[Path]:
    for parent in (source.parent, *source.parents):
        candidate = parent / "Cargo.toml"
        if candidate.is_file():
            return candidate
    return None


def rust_cargo_plan(project_root: Path, source: Path) -> Optional[ProjectBuildPlan]:
    """Return a Cargo plan only for a locked, explicit binary mapping.

    ``source`` may be absolute or relative to ``project_root``.  A lockfile is
    mandatory because builds are run offline; this avoids silently resolving a
    different dependency graph on the build host.
    """

    root = project_root.resolve()
    source_path = source if source.is_absolute() else root / source
    source_path = source_path.resolve()
    try:
        source_rel = source_path.relative_to(root)
    except ValueError:
        return None
    if source_path.suffix.lower() != ".rs" or not source_path.is_file():
        return None
    manifest = _nearest_manifest(source_path)
    if manifest is None or manifest.parent != root:
        # A project root must be the Cargo package root.  Workspace discovery
        # is intentionally left to an explicit caller rather than guessed.
        return None
    lockfile = root / "Cargo.lock"
    if not lockfile.is_file():
        return None
    binary_name = _cargo_binary_name(manifest, source_rel)
    if not binary_name or "/" in binary_name or "\\" in binary_name:
        return None
    cargo = shutil.which("cargo")
    if cargo is None:
        return None
    return ProjectBuildPlan(
        language="rust",
        kind="cargo",
        project_root=root,
        source_files=(source_rel,),
        artifact_name=binary_name,
        command=(cargo, "build", "--offline", "--locked", "--bin", binary_name),
        manifest=manifest,
        declaration=manifest,
    )


def _docker_logical_lines(dockerfile: Path) -> Iterable[str]:
    """Yield Dockerfile instructions with escaped continuation lines joined."""
    pending = ""
    try:
        lines = dockerfile.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if pending:
            pending += " " + stripped
        else:
            pending = stripped
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        yield pending
        pending = ""
    if pending:
        yield pending


def _go_build_tokens(instruction: str) -> Optional[List[str]]:
    if not instruction.upper().startswith("RUN "):
        return None
    shell = instruction[4:].strip()
    # Extract the actual `go build` segment from `cd ... && go build ...` or
    # `go build ... && ...`; quote handling is intentionally delegated to
    # shlex after the bounded segment is selected.
    match = re.search(r"\bgo\s+build\b(?P<args>.*?)(?:\s*(?:&&|;|$))", shell)
    if not match:
        return None
    args = match.group("args").strip()
    # In ``RUN sh -c "go build ..."`` the regex starts at the nested command,
    # so the shell's closing quote is left on the captured tail.
    if args.endswith(("\"", "\'")) and args.count(args[-1]) == 1:
        args = args[:-1].rstrip()
    try:
        return shlex.split("go build " + args)
    except ValueError:
        return None


def _go_build_mapping(tokens: Sequence[str], root: Path) -> Optional[Tuple[str, Tuple[Path, ...]]]:
    if len(tokens) < 2 or tokens[0:2] != ["go", "build"]:
        return None
    output: Optional[str] = None
    sources: List[Path] = []
    index = 2
    while index < len(tokens):
        token = tokens[index]
        if token == "-o" and index + 1 < len(tokens):
            output = tokens[index + 1]
            index += 2
            continue
        if token.startswith("-o="):
            output = token[3:]
            index += 1
            continue
        if token.startswith("-"):
            # Flags with a following value (for example -ldflags) remain in
            # the command but are irrelevant to source mapping.  A value that
            # looks like a .go file is still treated as a source below.
            index += 1
            continue
        if token == ".":
            sources.extend(sorted(path.relative_to(root) for path in root.glob("*.go") if path.is_file() and not path.name.endswith("_test.go")))
        elif token.endswith(".go"):
            candidate = (root / token).resolve()
            try:
                sources.append(candidate.relative_to(root))
            except ValueError:
                return None
        index += 1
    if not output or not sources:
        return None
    artifact = Path(output).name
    if not artifact or artifact in {".", ".."} or "/" in artifact or "\\" in artifact:
        return None
    unique_sources = tuple(dict.fromkeys(sources))
    if any(not (root / path).is_file() for path in unique_sources):
        return None
    return artifact, unique_sources


def go_dockerfile_plan(project_root: Path, dockerfile: Optional[Path] = None) -> Optional[ProjectBuildPlan]:
    """Map an explicit Dockerfile ``RUN go build`` to its listed Go sources.

    A Dockerfile that merely copies a prebuilt executable (as gopherz does) is
    deliberately unsupported.  This function never infers a command from the
    presence of ``*.go`` files or from a matching native binary.
    """

    root = project_root.resolve()
    docker = (root / "Dockerfile") if dockerfile is None else dockerfile
    docker = docker.resolve()
    if not docker.is_file() or docker.parent != root:
        return None
    for instruction in _docker_logical_lines(docker):
        tokens = _go_build_tokens(instruction)
        if not tokens:
            continue
        mapping = _go_build_mapping(tokens, root)
        if mapping is None:
            continue
        artifact, sources = mapping
        go = shutil.which("go")
        if go is None:
            return None
        # Keep all build flags from the Dockerfile command after `go build`;
        # rewrite only `-o` to a deterministic temporary artifact name.
        command = list(tokens)
        for index, token in enumerate(command):
            if token == "-o" and index + 1 < len(command):
                command[index + 1] = artifact
            elif token.startswith("-o="):
                command[index] = "-o=" + artifact
        command[0] = go
        return ProjectBuildPlan(
            language="go",
            kind="dockerfile-go-build",
            project_root=root,
            source_files=sources,
            artifact_name=artifact,
            command=tuple(command),
            declaration=docker,
        )
    return None


def _detached_copy(source: Path, destination: Path) -> None:
    """Copy every project file to independent storage before compiling."""
    shutil.copytree(source, destination, symlinks=True)


def execute_project_build(
    plan: ProjectBuildPlan,
    output_path: Path,
    *,
    timeout: int = 180,
) -> ProjectBuildResult:
    """Build a plan in a detached temporary copy and install its artifact.

    The output is replaced only after a successful command and a regular-file
    artifact is present.  Existing project files are never modified.
    """

    compiler = plan.command[0]
    if not shutil.which(compiler) and not Path(compiler).is_file():
        return ProjectBuildResult(False, None, plan.command, reason=f"build tool unavailable: {compiler}")
    output_path = output_path.resolve()
    with tempfile.TemporaryDirectory(prefix="mybench-project-") as temporary:
        detached = Path(temporary) / "project"
        _detached_copy(plan.project_root, detached)
        target = detached / plan.artifact_name
        if plan.kind == "cargo":
            command = (*plan.command, "--manifest-path", str(detached / "Cargo.toml"), "--target-dir", str(detached / ".mybench-target"))
            expected = detached / ".mybench-target" / "debug" / plan.artifact_name
            cwd = detached
        else:
            command = plan.command
            command = tuple(str(detached / token) if token == plan.artifact_name else token for token in command)
            expected = target
            cwd = detached
        try:
            result = subprocess.run(
                command,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ProjectBuildResult(False, None, tuple(command), reason=str(exc))
        if result.returncode != 0 or not expected.is_file():
            return ProjectBuildResult(
                False,
                None,
                tuple(command),
                stdout=result.stdout[-4000:],
                reason=f"build returned {result.returncode} or artifact was not produced",
            )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        before = _sha256(output_path) if output_path.is_file() else None
        temporary_output = output_path.with_name(output_path.name + ".mybench-build")
        if temporary_output.exists():
            temporary_output.unlink()
        shutil.copy2(expected, temporary_output)
        temporary_output.replace(output_path)
        changed = before != _sha256(output_path)
        return ProjectBuildResult(changed, output_path, tuple(command), stdout=result.stdout[-4000:])
