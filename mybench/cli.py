from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Optional, Sequence

from .discovery import discover
from .mutators import _normalize_noise_policy, generate
from .validator import validate_tree


def _path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _load_noise_policy(path: Optional[Path]) -> Optional[dict]:
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("noise policy must be a JSON object")
    if "noise_policy" in payload:
        payload = payload["noise_policy"]
    if not isinstance(payload, dict):
        raise ValueError("noise_policy must be a JSON object")
    return _normalize_noise_policy(payload)


def _add_source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ctfbench", type=_path, required=True, help="path to the CTFbench checkout")
    parser.add_argument("--split", choices=["development", "test", "all"], default="all")
    parser.add_argument("--category", nargs="+", choices=["pwn", "rev"], default=["pwn", "rev"])


def _discover(args: argparse.Namespace) -> int:
    seeds = discover(args.ctfbench, args.split, args.category)
    print(json.dumps({"count": len(seeds), "seeds": [seed.to_dict() for seed in seeds]}, indent=2, ensure_ascii=False))
    return 0


def _generate(args: argparse.Namespace) -> int:
    if args.output.exists() and args.clean:
        if args.output.resolve() in {Path("/").resolve(), Path.home().resolve()}:
            raise SystemExit("refusing to clean a filesystem root or home directory")
        shutil.rmtree(args.output)
    args.output.mkdir(parents=True, exist_ok=True)
    seeds = discover(args.ctfbench, args.split, args.category)
    noise_policy = _load_noise_policy(args.noise_policy)
    created = generate(seeds, args.output, args.variants_per_seed, noise_policy=noise_policy)
    catalog = {
        "schema_version": 1,
        "ctfbench_root": str(args.ctfbench),
        "split": args.split,
        "categories": args.category,
        "seeds": len(seeds),
        "variants": len(created),
        "variants_per_seed": args.variants_per_seed,
        "variant_paths": [path.relative_to(args.output).as_posix() for path in created],
        "seed_inventory": [seed.to_dict() for seed in seeds],
        "noise_policy": _normalize_noise_policy(noise_policy),
    }
    (args.output / "catalog.json").write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"generated {len(created)} variants from {len(seeds)} seeds at {args.output}")
    return 0


def _validate(args: argparse.Namespace) -> int:
    report = validate_tree(args.input, build=args.build)
    print(json.dumps({
        k: report[k]
        for k in (
            "status", "variants", "passed", "failed",
            "substantive_artifact_mutations", "source_mutations_checked",
        )
    }, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def _pipeline(args: argparse.Namespace) -> int:
    if args.output.exists() and args.clean:
        if args.output.resolve() in {Path("/").resolve(), Path.home().resolve()}:
            raise SystemExit("refusing to clean a filesystem root or home directory")
        shutil.rmtree(args.output)
    args.output.mkdir(parents=True, exist_ok=True)
    seeds = discover(args.ctfbench, args.split, args.category)
    noise_policy = _load_noise_policy(args.noise_policy)
    created = generate(seeds, args.output, args.variants_per_seed, noise_policy=noise_policy)
    catalog = {
        "schema_version": 1,
        "ctfbench_root": str(args.ctfbench),
        "split": args.split,
        "categories": args.category,
        "seeds": len(seeds),
        "variants": len(created),
        "variants_per_seed": args.variants_per_seed,
        "variant_paths": [path.relative_to(args.output).as_posix() for path in created],
        "seed_inventory": [seed.to_dict() for seed in seeds],
        "noise_policy": _normalize_noise_policy(noise_policy),
    }
    (args.output / "catalog.json").write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report = validate_tree(args.output, build=args.build)
    print(json.dumps({
        k: report[k]
        for k in (
            "status", "variants", "passed", "failed",
            "substantive_artifact_mutations", "source_mutations_checked",
        )
    }, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Automatically mutate and validate CTFbench pwn/rev seeds")
    sub = parser.add_subparsers(dest="command", required=True)

    discover_parser = sub.add_parser("discover", help="enumerate pwn/rev seeds from dataset JSON")
    _add_source_args(discover_parser)
    discover_parser.set_defaults(func=_discover)

    generate_parser = sub.add_parser("generate", help="materialize deterministic variants")
    _add_source_args(generate_parser)
    generate_parser.add_argument("--output", type=_path, required=True)
    generate_parser.add_argument("--variants-per-seed", type=int, default=1)
    generate_parser.add_argument("--noise-policy", type=_path)
    generate_parser.add_argument("--clean", action="store_true")
    generate_parser.set_defaults(func=_generate)

    validate_parser = sub.add_parser("validate", help="validate generated variants")
    validate_parser.add_argument("--input", type=_path, required=True)
    validate_parser.add_argument("--build", action="store_true", help="also run make when a Makefile exists")
    validate_parser.set_defaults(func=_validate)

    pipeline_parser = sub.add_parser("pipeline", help="generate and validate in one command")
    _add_source_args(pipeline_parser)
    pipeline_parser.add_argument("--output", type=_path, required=True)
    pipeline_parser.add_argument("--variants-per-seed", type=int, default=1)
    pipeline_parser.add_argument("--noise-policy", type=_path)
    pipeline_parser.add_argument("--clean", action="store_true")
    pipeline_parser.add_argument("--build", action="store_true")
    pipeline_parser.set_defaults(func=_pipeline)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "variants_per_seed", 1) < 1:
        parser.error("--variants-per-seed must be >= 1")
    try:
        return args.func(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"mybench: {exc}", file=sys.stderr)
        return 2
