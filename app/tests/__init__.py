"""
Suite de Pruebas Automatizadas de Seguridad, Criptografía, Sesiones, RBAC y Auditoría Forense.
Compatible con ejecución vía `pytest` y `python3 -m unittest`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
_APP_DIR = _TESTS_DIR.parent
_PROJECT_ROOT = _APP_DIR.parent
_PY_VER = f"python{sys.version_info.major}.{sys.version_info.minor}"
_VENV_DIRS = [
    *(
        [Path(os.environ["VIRTUAL_ENV"])]
        if os.environ.get("VIRTUAL_ENV")
        else []
    ),
    _PROJECT_ROOT / ".venv",
    _PROJECT_ROOT / "venv",
    _PROJECT_ROOT / "entorno-contrato",
]
_SYS_SITE = Path(f"/usr/lib/{_PY_VER}/site-packages")

for _candidate in (
    _PROJECT_ROOT,
    *(d / "lib" / _PY_VER / "site-packages" for d in _VENV_DIRS),
    _SYS_SITE,
):
    _path_str = str(_candidate)
    if _candidate.exists() and _path_str not in sys.path:
        sys.path.insert(0, _path_str)
