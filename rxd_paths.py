"""
Shared storage paths for RxD user settings.

Keeps user-created data out of the project folder and in a predictable,
cross-platform Documents/RxD directory.
"""

import os
import shutil
from pathlib import Path


def get_rxd_documents_dir():
    """Return the Documents/RxD folder, falling back to ~/RxD if needed."""
    home = Path.home()
    documents = home / "Documents"
    base = documents if documents.exists() or _safe_mkdir(documents) else home
    rxd_dir = base / "RxD"
    _safe_mkdir(rxd_dir)
    return rxd_dir


def _safe_mkdir(path):
    try:
        path.mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def storage_path(filename):
    """Return an absolute path inside Documents/RxD."""
    return str(get_rxd_documents_dir() / filename)


def storage_dir(dirname):
    """Return an absolute directory path inside Documents/RxD."""
    path = get_rxd_documents_dir() / dirname
    _safe_mkdir(path)
    return str(path)


def migrated_storage_dir(dirname, legacy_dirs=None):
    """Return a storage directory, copying existing legacy contents once."""
    target = Path(storage_dir(dirname))
    for legacy in legacy_dirs or []:
        legacy_path = Path(os.path.expanduser(str(legacy)))
        try:
            if legacy_path.exists() and legacy_path.is_dir():
                shutil.copytree(str(legacy_path), str(target), dirs_exist_ok=True)
        except Exception:
            pass
    return str(target)


def migrated_storage_path(filename, legacy_paths=None):
    """Return a storage path, copying the first existing legacy file once."""
    target = Path(storage_path(filename))
    if not target.exists():
        for legacy in legacy_paths or []:
            legacy_path = Path(os.path.expanduser(str(legacy)))
            try:
                if legacy_path.exists() and legacy_path.is_file():
                    shutil.copy2(str(legacy_path), str(target))
                    break
            except Exception:
                pass
    return str(target)
