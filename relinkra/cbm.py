"""CBM identity-boundary helpers for Relinkra.

Minimal adapter only: it records CBM's path-derived identity unchanged
(project name slug + cache dir + db path + optional binary info). Relinkra
does NOT reimplement the CBM slug, does NOT query the graph, and does NOT
replace CBM identity — the logical project layers above it.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass(frozen=True)
class CBMBinaryInfo:
    version: Optional[str] = None
    sha256: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class CBMProjectIdentity:
    project_name: str  # CBM path-derived slug, recorded unchanged
    cache_dir: str
    db_path: str
    binary: CBMBinaryInfo = field(default_factory=CBMBinaryInfo)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["binary"] = self.binary.to_dict()
        return d


def cbm_db_path(cache_dir: str, project_name: str) -> str:
    return os.path.join(cache_dir, f"{project_name}.db")


def workspace_cbm_record(
    project_name: str,
    cache_dir: str,
    version: Optional[str] = None,
    sha256: Optional[str] = None,
) -> CBMProjectIdentity:
    return CBMProjectIdentity(
        project_name=project_name,
        cache_dir=cache_dir,
        db_path=cbm_db_path(cache_dir, project_name),
        binary=CBMBinaryInfo(version=version, sha256=sha256),
    )
