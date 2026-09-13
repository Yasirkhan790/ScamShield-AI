from fastapi import APIRouter, HTTPException, Query

from app.database.history_repository import get_analysis, list_analyses
from app.models.analysis import HistoryDetail, HistoryListItem

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("", response_model=list[HistoryListItem])
def history_endpoint(limit: int = Query(default=20, ge=1, le=100)):
    return list_analyses(limit=limit)


@router.get("/{record_id}", response_model=HistoryDetail)
def history_detail_endpoint(record_id: int):
    record = get_analysis(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    return record
