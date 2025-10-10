from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import PlainTextResponse
from typing import Optional, List
import os, psycopg, csv, io
from datetime import datetime, date, timezone

router = APIRouter()

def pg():
    return psycopg.connect(os.getenv("DATABASE_URL"), autocommit=False)

def _parse_utc(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO date/datetime as UTC. If date-only, assume 00:00:00Z."""
    if not ts:
        return None
    try:
        if len(ts) == 10:  # yyyy-mm-dd
            d = date.fromisoformat(ts)
            return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
        s = ts.replace("Z", "+00:00")  # normalize trailing Z
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid timestamp: {ts}")

@router.get("/merchant/receipts")
def merchant_receipts(
    merchant_id: str,
    since: Optional[str] = None,   # ISO date or datetime
    until: Optional[str] = None,   # ISO date or datetime
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    ts_since = _parse_utc(since)
    ts_until = _parse_utc(until)

    q = """
      SELECT merchant_id, kind, code, amount_cents, at_utc
        FROM v_txn_flat
       WHERE merchant_id = %s
         AND at_utc >= COALESCE(%s::timestamp, '-infinity'::timestamp)
         AND at_utc <  COALESCE(%s::timestamp,  'infinity'::timestamp)
       ORDER BY at_utc DESC
       LIMIT %s OFFSET %s
    """
    with pg() as conn, conn.cursor() as cur:
        cur.execute(q, (merchant_id, ts_since, ts_until, limit, offset))
        rows = cur.fetchall()
    return [
        {
            "merchant_id": r[0],
            "kind": r[1],
            "code": r[2],
            "amount_cents": int(r[3]),
            "at_utc": r[4].isoformat(),
        }
        for r in rows
    ]

@router.get("/admin/reports/merchant_daily.csv", response_class=PlainTextResponse)
def merchant_daily_csv(
    merchant_id: Optional[str] = None,
    day: Optional[str] = None,        # yyyy-mm-dd (UTC)
    since_day: Optional[str] = None,  # yyyy-mm-dd (UTC)
    until_day: Optional[str] = None,  # yyyy-mm-dd (UTC, exclusive)
):
    where = []
    params: List[object] = []

    if merchant_id:
        where.append("merchant_id = %s")
        params.append(merchant_id)

    if day:
        where.append("day_utc = %s::date")
        params.append(day)
    else:
        if since_day:
            where.append("day_utc >= %s::date")
            params.append(since_day)
        if until_day:
            where.append("day_utc < %s::date")
            params.append(until_day)

    sql = """
      SELECT merchant_id, day_utc, issued_cents, redeemed_cents, net_cents
        FROM v_merchant_daily
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY day_utc, merchant_id"

    with pg() as conn, conn.cursor() as cur:
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["merchant_id","day_utc","issued_cents","redeemed_cents","net_cents"])
    for r in rows:
        # r[1] is a date (from view), so .isoformat() is safe
        w.writerow([r[0], r[1].isoformat(), int(r[2]), int(r[3]), int(r[4])])
    return buf.getvalue()
