"""Vulnerability Assessment Module: matches detected service/version against the offline CVE
dataset, and also loads a dataclass view usable without a DB session (e.g. for unit tests).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.db.models import CveRecord, Severity

DATASET_PATH = Path(__file__).parent / "cve_data" / "offline_cve_dataset.json"


@dataclass
class CveMatch:
    cve_id: str
    title: str
    description: str
    cvss_score: float
    severity: str
    reference_url: str | None = None


def load_offline_dataset() -> list[dict]:
    """Load the raw curated CVE records from the bundled JSON dataset."""
    with DATASET_PATH.open(encoding="utf-8") as f:
        data = json.load(f)
    return data["records"]


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_satisfies(detected_version: str | None, rule: str) -> bool:
    """Evaluate a dataset `affected_version` rule against a detected version string.

    Rules:
      "*"        -> always matches (used for protocol/config-level findings)
      "<=X.Y.Z"  -> matches if detected_version <= X.Y.Z numerically
      "1.2.3"    -> matches if detected_version starts with that exact string
    """
    if rule == "*":
        return True
    if detected_version is None:
        return False
    if rule.startswith("<="):
        try:
            return _version_tuple(detected_version) <= _version_tuple(rule[2:])
        except (ValueError, TypeError):
            return False
    return detected_version.strip().startswith(rule.strip())


def match_offline_records(product: str | None, version: str | None) -> list[dict]:
    """Match against the raw JSON dataset (no DB required) -- used by unit tests and seeding."""
    if not product:
        return []
    product_norm = product.strip().lower()
    matches = []
    for record in load_offline_dataset():
        if record["product"].lower() not in product_norm and product_norm not in record["product"].lower():
            continue
        if _version_satisfies(version, record["affected_version"]):
            matches.append(record)
    return matches


def match_cves(session: Session, product: str | None, version: str | None) -> list[CveMatch]:
    """Match a detected service `product`/`version` against CVE records stored in the DB."""
    if not product:
        return []
    product_norm = product.strip().lower()
    candidates = session.query(CveRecord).all()
    results: list[CveMatch] = []
    for rec in candidates:
        rec_product = rec.product.lower()
        if rec_product not in product_norm and product_norm not in rec_product:
            continue
        if _version_satisfies(version, rec.affected_version):
            severity = rec.severity.value if isinstance(rec.severity, Severity) else str(rec.severity)
            results.append(
                CveMatch(
                    cve_id=rec.cve_id,
                    title=f"{rec.product} {rec.affected_version}: {rec.cve_id}",
                    description=rec.description,
                    cvss_score=rec.cvss_score,
                    severity=severity,
                    reference_url=rec.reference_url,
                )
            )
    return results
