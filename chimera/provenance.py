from __future__ import annotations

import hashlib
import os
from pathlib import Path

from chimera.config import ExperimentConfig


REPO_ROOT = Path(__file__).resolve().parents[1]


def current_model_ids(config: ExperimentConfig) -> dict[str, str | None]:
    return {
        "attacker": os.getenv(config.models.attacker.model_env, "").strip() or None,
        "defender": os.getenv(config.models.defender.model_env, "").strip() or None,
    }


def current_source_tree_digest(repository: Path = REPO_ROOT) -> str:
    digest = hashlib.sha256()
    repository = Path(repository).absolute()
    files = _verification_source_files(repository)
    if not files:
        raise ValueError("verification source tree is empty")
    for path in files:
        relative = path.relative_to(repository).as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def _verification_source_files(repository: Path) -> tuple[Path, ...]:
    repository = repository.absolute()
    selected: list[Path] = []
    roots = ("chimera", "range", "prompts", "tests", "configs")
    for root_name in roots:
        root = repository / root_name
        if root.is_symlink() or not root.is_dir():
            raise ValueError(f"verification source root is unsafe: {root_name}")
        for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
            directory_path = Path(directory)
            retained: list[str] = []
            for name in sorted(names):
                candidate = directory_path / name
                relative = candidate.relative_to(repository)
                if candidate.is_symlink():
                    raise ValueError("verification source tree contains a symlink")
                if name in {"__pycache__", ".pytest_cache"}:
                    continue
                if relative.parts[:2] == ("range", "runtime"):
                    continue
                retained.append(name)
            names[:] = retained
            for filename in sorted(filenames):
                candidate = directory_path / filename
                if candidate.is_symlink():
                    raise ValueError("verification source tree contains a symlink")
                if (
                    not candidate.is_file()
                    or filename == ".DS_Store"
                    or candidate.suffix == ".pyc"
                ):
                    continue
                if root_name == "tests" and candidate.suffix != ".py":
                    continue
                selected.append(candidate)
    pyproject = repository / "pyproject.toml"
    if pyproject.is_symlink() or not pyproject.is_file():
        raise ValueError("verification source pyproject.toml is unsafe or missing")
    selected.append(pyproject)
    return tuple(
        sorted(selected, key=lambda path: path.relative_to(repository).as_posix())
    )
