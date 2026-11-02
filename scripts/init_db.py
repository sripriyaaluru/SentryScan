"""Create all database tables. Run once after configuring DATABASE_URL in .env.

Usage:
    python scripts/init_db.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import models  # noqa: F401  (import registers models with Base.metadata)
from app.db.base import Base, engine


def main() -> None:
    print(f"Creating tables on {engine.url.render_as_string(hide_password=True)} ...")
    Base.metadata.create_all(engine)
    print("Done. Tables:", ", ".join(sorted(Base.metadata.tables.keys())))


if __name__ == "__main__":
    main()
