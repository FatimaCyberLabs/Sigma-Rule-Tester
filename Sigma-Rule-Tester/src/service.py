"""Casos de uso comunes: carga, normalizacion, estadisticas y exportacion."""
from __future__ import annotations
import json
import logging
from collections import Counter
from pathlib import Path
from .models import Finding
LOGGER = logging.getLogger(__name__)

# Reglas simplificadas estilo Sigma: nombre -> subcadena que debe aparecer en la linea
BUILTIN_RULES = {
    "failed_ssh_login": "Failed password",
    "successful_ssh_login": "Accepted",
    "sudo_privilege_use": "sudo",
}

class Service:
    """Base reutilizable para adaptadores especificos de cada herramienta."""
    def inspect(self, target: Path) -> list[Finding]:
        if not target.exists(): raise FileNotFoundError(target)
        findings: list[Finding] = []
        for raw in target.read_text(encoding="utf-8", errors="ignore").splitlines():
            for rule_name, pattern in BUILTIN_RULES.items():
                if pattern in raw:
                    findings.append(Finding(category=f"rule_match:{rule_name}", value=raw.strip(), source=str(target), severity="medium"))
        return findings
    @staticmethod
    def export(findings: list[Finding], destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps([item.to_dict() for item in findings], indent=2) + "\n", encoding="utf-8")
    @staticmethod
    def stats(findings: list[Finding]) -> dict[str, object]:
        return {"total": len(findings), "by_category": dict(Counter(item.category for item in findings)), "by_severity": dict(Counter(item.severity for item in findings))}
