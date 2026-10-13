from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


SOURCE_SUFFIXES = {
    ".c", ".h", ".cc", ".hh", ".cpp", ".hpp", ".cxx", ".hxx",
    ".rs", ".go", ".py", ".js", ".jsx", ".ts", ".tsx", ".java",
    ".rb", ".swift", ".m", ".mm", ".sol",
}


@dataclass
class Seed:
    """A normalized CTFbench seed challenge."""

    dataset_key: str
    split: str
    category: str
    ctfbench_root: Path
    seed_path: Path
    metadata: Dict[str, Any]
    dataset_metadata: Dict[str, Any]
    source_files: List[Path] = field(default_factory=list)
    declared_files: List[Path] = field(default_factory=list)
    solver_files: List[Path] = field(default_factory=list)
    has_makefile: bool = False
    has_dockerfile: bool = False

    @property
    def relative_seed_path(self) -> str:
        return self.seed_path.relative_to(self.ctfbench_root).as_posix()

    @property
    def challenge_json(self) -> Path:
        return self.seed_path / "challenge.json"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_key": self.dataset_key,
            "split": self.split,
            "category": self.category,
            "seed_path": self.relative_seed_path,
            "name": self.metadata.get("name"),
            "description": self.metadata.get("description"),
            "source_files": [p.relative_to(self.seed_path).as_posix() for p in self.source_files],
            "declared_files": [p.relative_to(self.seed_path).as_posix() for p in self.declared_files],
            "solver_files": [p.relative_to(self.seed_path).as_posix() for p in self.solver_files],
            "has_makefile": self.has_makefile,
            "has_dockerfile": self.has_dockerfile,
        }
