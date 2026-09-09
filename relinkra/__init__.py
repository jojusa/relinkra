"""Relinkra — portable logical project identity above path-derived CBM identity."""

from .identity import (
    AmbiguousIdentityError,
    CASE_INSENSITIVE_HOSTS,
    LogicalProject,
    RepositoryIdentity,
    Workspace,
    canonicalize_path,
    choose_remote,
    derive_project_id,
    derive_workspace_id,
    discover_repository_identity,
    explicit_identity,
    local_root_identity,
    normalize_os_family,
    normalize_remote_url,
    redact_url,
)
from .registry import Registry, RegistryError
from .cbm import CBMBinaryInfo, CBMProjectIdentity, cbm_db_path, workspace_cbm_record

__version__ = "0.1.1"

__all__ = [
    "AmbiguousIdentityError",
    "CASE_INSENSITIVE_HOSTS",
    "CBMBinaryInfo",
    "CBMProjectIdentity",
    "LogicalProject",
    "Registry",
    "RegistryError",
    "RepositoryIdentity",
    "Workspace",
    "canonicalize_path",
    "cbm_db_path",
    "choose_remote",
    "derive_project_id",
    "derive_workspace_id",
    "discover_repository_identity",
    "explicit_identity",
    "local_root_identity",
    "normalize_os_family",
    "normalize_remote_url",
    "redact_url",
    "workspace_cbm_record",
]
