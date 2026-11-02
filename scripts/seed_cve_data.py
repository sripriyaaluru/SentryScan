"""Load the bundled offline CVE dataset into the `cve_records` table.

Safe to re-run: existing records (matched by cve_id) are updated in place rather than duplicated.

Usage:
    python scripts/seed_cve_data.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.base import SessionLocal
from app.db.models import CveRecord, Severity
from app.modules.vuln_assessment.cve_matcher import load_offline_dataset


def main() -> None:
    records = load_offline_dataset()
    session = SessionLocal()
    inserted = 0
    updated = 0
    try:
        for rec in records:
            existing = session.query(CveRecord).filter_by(cve_id=rec["cve_id"]).one_or_none()
            severity = Severity(rec["severity"])
            if existing:
                existing.product = rec["product"]
                existing.affected_version = rec["affected_version"]
                existing.description = rec["description"]
                existing.cvss_score = rec["cvss_score"]
                existing.severity = severity
                existing.reference_url = rec.get("reference_url")
                updated += 1
            else:
                session.add(
                    CveRecord(
                        cve_id=rec["cve_id"],
                        product=rec["product"],
                        affected_version=rec["affected_version"],
                        description=rec["description"],
                        cvss_score=rec["cvss_score"],
                        severity=severity,
                        reference_url=rec.get("reference_url"),
                    )
                )
                inserted += 1
        session.commit()
    finally:
        session.close()
    print(f"Seed complete: {inserted} inserted, {updated} updated, {len(records)} total records.")


if __name__ == "__main__":
    main()
