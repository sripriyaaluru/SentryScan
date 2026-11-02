"""Shared FastAPI dependencies."""
from app.db.base import get_db

__all__ = ["get_db"]
