"""Target CRUD endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.authorization import is_target_authorized
from app.db.models import Target
from app.schemas.schemas import TargetCreate, TargetOut

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)) -> Target:
    """Register a new target. The response's `is_authorized` field reflects a live check
    against AUTHORIZED_TARGETS -- it does not grant any new permission by itself."""
    target = Target(name=payload.name, host=payload.host, description=payload.description)
    db.add(target)
    db.commit()
    db.refresh(target)
    return _with_authorization(target)


@router.get("", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db)) -> list[Target]:
    """List all targets, newest first, each annotated with its current authorization status."""
    targets = db.query(Target).order_by(Target.created_at.desc()).all()
    return [_with_authorization(t) for t in targets]


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db)) -> Target:
    """Fetch a single target by id, 404 if it doesn't exist."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return _with_authorization(target)


@router.delete("/{target_id}", status_code=204, response_model=None)
def delete_target(target_id: int, db: Session = Depends(get_db)) -> None:
    """Delete a target and cascade-delete its scan jobs and all related findings."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()


def _with_authorization(target: Target) -> Target:
    """Attach a transient `is_authorized` attribute (not persisted) for the response model."""
    target.is_authorized = is_target_authorized(target.host)  # type: ignore[attr-defined]
    return target
