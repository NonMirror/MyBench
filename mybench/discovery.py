from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Sequence

from .model import SOURCE_SUFFIXES, Seed


def _iter_files(root: Path) -> Iterable[Path]:
    ignored_parts = {".git", "node_modules", "__pycache__", ".venv"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            relative_parts = set(path.relative_to(root).parts)
        except ValueError:
            continue
        if relative_parts & ignored_parts:
            continue
        yield path


def _source_score(path: Path) -> tuple:
    name = path.name.lower()
    rel = "/".join(part.lower() for part in path.parts)
    score = 0
    if name in {"main.c", "main.cpp", "main.cc", "challenge.c", "challenge.cpp", "chal.c", "chal.cpp"}:
        score += 100
    if path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".go", ".rs"}:
        score += 35
    if any(part in rel for part in ("/src/", "/source/", "/src", "/source")):
        score += 20
    if any(token in name for token in ("challenge", "chall", "target", "program", "binary")):
        score += 15
    if name in {"solution.py", "solve.py", "solver.py", "solution.cpp", "solve.cpp"}:
        score -= 100
    if any(part in rel for part in ("test_solver", "solution", "soln", "dist", "vendor", "build", "writeup")):
        score -= 80
    if any(token in name for token in ("poc", "exploit", "writeup", "solver", "solution", "test")):
        score -= 50
    score -= len(path.parts)
    return (-score, path.stat().st_size, rel)


def _is_candidate_source(path: Path) -> bool:
    rel = "/".join(part.lower() for part in path.parts)
    name = path.name.lower()
    if any(part in rel for part in ("/test_solver/", "/solution/", "/soln/", "/writeup/")):
        return False
    if name in {"solve.py", "solver.py", "solution.py", "solve.sh", "solution.sh"}:
        return False
    if any(token in name for token in ("poc", "exploit", "solver", "solution", "writeup")):
        return False
    if name.startswith("flag") or name.startswith("answer"):
        return False
    return True


def _normalize_splits(split: str) -> Sequence[str]:
    if split == "all":
        return ("development", "test")
    if split not in {"development", "test"}:
        raise ValueError("split must be development, test, or all")
    return (split,)


def discover(
    ctfbench_root: Path,
    split: str = "all",
    categories: Sequence[str] = ("pwn", "rev"),
) -> List[Seed]:
    """Discover seeds from the authoritative CTFbench dataset JSON files."""

    root = ctfbench_root.resolve()
    wanted = {c.lower() for c in categories}
    seeds: List[Seed] = []
    for current_split in _normalize_splits(split):
        dataset_path = root / f"{current_split}_dataset.json"
        if not dataset_path.exists():
            raise FileNotFoundError(f"missing dataset: {dataset_path}")
        dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
        if not isinstance(dataset, dict):
            raise ValueError(f"dataset must be an object: {dataset_path}")
        for dataset_key, dataset_metadata in dataset.items():
            category = str(dataset_metadata.get("category", "")).lower()
            if category not in wanted:
                continue
            relative_path = dataset_metadata.get("path")
            if not relative_path:
                continue
            seed_path = root / relative_path
            challenge_json = seed_path / "challenge.json"
            if not seed_path.is_dir() or not challenge_json.exists():
                raise FileNotFoundError(
                    f"dataset entry {dataset_key} does not resolve to a challenge: {relative_path}"
                )
            metadata = json.loads(challenge_json.read_text(encoding="utf-8"))
            files = list(_iter_files(seed_path))
            source_files = sorted(
                (p for p in files if p.suffix.lower() in SOURCE_SUFFIXES and _is_candidate_source(p)),
                key=_source_score,
            )
            declared_files = []
            for declared in metadata.get("files", []) or []:
                path = seed_path / str(declared)
                if path.exists() and path.is_file():
                    declared_files.append(path)
            solver_names = {"solve.py", "solver.py", "solution.py", "solve.sh", "solution.sh"}
            solver_files = sorted(
                p for p in files
                if p.name in solver_names or "test_solver" in p.parts
            )
            has_makefile = any(p.name.lower() in {"makefile", "gnumakefile"} for p in files)
            has_dockerfile = any(p.name.lower() == "dockerfile" for p in files)
            seeds.append(
                Seed(
                    dataset_key=dataset_key,
                    split=current_split,
                    category=category,
                    ctfbench_root=root,
                    seed_path=seed_path,
                    metadata=metadata,
                    dataset_metadata=dataset_metadata,
                    source_files=source_files,
                    declared_files=declared_files,
                    solver_files=solver_files,
                    has_makefile=has_makefile,
                    has_dockerfile=has_dockerfile,
                )
            )
    return sorted(seeds, key=lambda s: (s.category, s.split, s.dataset_key))
