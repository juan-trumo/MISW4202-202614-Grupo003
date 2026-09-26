"""Utilidades para pruebas unitarias de los servicios. No se usan en producción."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from common.errors import ApiError

ROOT = Path(__file__).resolve().parent.parent
# Módulos locales de cada servicio: se llaman igual en todos (app, models...), así que se
# descartan de sys.modules antes de cargar otro servicio en la misma sesión de pytest.
_LOCAL_MODULES = ("app", "models", "seed", "passwords")


def load_service_app(service: str) -> ModuleType:
    """Importa services/<service>/app.py como módulo aislado (lee el entorno al importarse)."""
    service_dir = ROOT / "services" / service
    for name in _LOCAL_MODULES:
        sys.modules.pop(name, None)
    sys.path.insert(0, str(service_dir))
    try:
        spec = importlib.util.spec_from_file_location(f"{service}_app", service_dir / "app.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(service_dir))
    return module


class FakeAudit:
    """Sustituye al AuditClient: guarda los eventos o simula audit-service caído."""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.down = False

    def record(self, **fields) -> None:
        if self.down:
            raise ApiError(503, "audit_unavailable", "simulado")
        self.events.append(fields)
