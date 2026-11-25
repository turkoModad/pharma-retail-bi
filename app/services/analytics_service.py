"""
Servicio Analítico de Alto Rendimiento sobre SQLite (`compras`, `productos`, `productos_comprados`).

Diseñado para ejecutarse con < 512 MB de RAM (Raspberry Pi Zero 2 W):
- Cero librerías pesadas (`pandas`, `numpy`).
- Agregaciones ejecutadas íntegramente en SQLite mediante SQL parametrizado e índices de cobertura.
- Estrictamente de solo lectura sobre las tablas comerciales (únicamente crea índices `IF NOT EXISTS`).
"""

from __future__ import annotations

import calendar
import re
from datetime import date, timedelta
from typing import Any, Dict, List

from sqlalchemy import text

from app.core.database import AsyncSession

ANALYTICS_INDEX_STATEMENTS: tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS idx_compras_fecha_cov ON compras (fecha, factura, precio_total, cant_fact, cant_entr, cant_ped)",
    "CREATE INDEX IF NOT EXISTS idx_compras_y_cov ON compras (substr(fecha, 1, 4), factura, precio_total, cant_fact, cant_entr, cant_ped)",
    "CREATE INDEX IF NOT EXISTS idx_compras_ym_cov ON compras (substr(fecha, 1, 7), fecha, factura, precio_total, cant_fact, cant_entr, cant_ped)",
    "CREATE INDEX IF NOT EXISTS idx_compras_prod_fecha_cov ON compras (producto_id, fecha DESC, precio_unitario, precio_total, cant_fact, cant_entr, cant_ped, factura)",
    "CREATE INDEX IF NOT EXISTS idx_compras_codigo ON compras (codigo)",
    "CREATE INDEX IF NOT EXISTS idx_productos_droga_norm ON productos (UPPER(TRIM(droga)), laboratorio, id)",
    "CREATE INDEX IF NOT EXISTS idx_productos_droga ON productos (droga)",
    "CREATE INDEX IF NOT EXISTS idx_productos_nombre ON productos (nombre)",
    "CREATE INDEX IF NOT EXISTS idx_productos_laboratorio ON productos (laboratorio)",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_event_created ON audit_logs (event_type, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created ON audit_logs (user_id, created_at DESC)",
)

_MONTH_NAMES_ES: tuple[str, ...] = (
    "",
    "Ene",
    "Feb",
    "Mar",
    "Abr",
    "May",
    "Jun",
    "Jul",
    "Ago",
    "Sep",
    "Oct",
    "Nov",
    "Dic",
)


def ensure_analytics_indexes_sync(sync_conn: Any) -> list[str]:
    """
    Crea de forma idempotente los índices de cobertura SQLite sobre `compras`, `productos`
    y `audit_logs` cuando dichas tablas existen en la base de datos.
    """
    existing_tables_rows = sync_conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table'")
    ).fetchall()
    existing_tables = {row[0] for row in existing_tables_rows}

    created: list[str] = []
    for ddl in ANALYTICS_INDEX_STATEMENTS:
        if " ON compras " in ddl and "compras" not in existing_tables:
            continue
        if " ON productos " in ddl and "productos" not in existing_tables:
            continue
        if " ON audit_logs " in ddl and "audit_logs" not in existing_tables:
            continue
        sync_conn.execute(text(ddl))
        idx_name = ddl.split("IF NOT EXISTS ", 1)[1].split(" ON ", 1)[0].strip()
        created.append(idx_name)
    return created


def _parse_iso_date(raw: str | None) -> date | None:
    if not raw or not str(raw).strip():
        return None
    cleaned = str(raw).strip()[:10]
    try:
        return date.fromisoformat(cleaned)
    except ValueError:
        return None


def _build_date_where(
    date_from: str | None,
    date_to: str | None,
    col: str = "fecha",
) -> tuple[str, dict[str, Any], date | None, date | None]:
    d_from = _parse_iso_date(date_from)
    d_to = _parse_iso_date(date_to)
    if d_from and d_to and d_from > d_to:
        d_from, d_to = d_to, d_from

    clauses: list[str] = []
    params: dict[str, Any] = {}
    if d_from is not None:
        clauses.append(f"{col} >= :d_from")
        params["d_from"] = f"{d_from.isoformat()} 00:00:00"
    if d_to is not None:
        clauses.append(f"{col} <= :d_to")
        params["d_to"] = f"{d_to.isoformat()} 23:59:59.999999"

    where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where_sql, params, d_from, d_to


def _compute_previous_period(d_from: date, d_to: date) -> tuple[date, date]:
    """Calcula el intervalo equivalente inmediatamente anterior para comparativa KPI."""
    if (
        d_from.month == 1
        and d_from.day == 1
        and d_to.month == 12
        and d_to.day == 31
        and d_from.year == d_to.year
    ):
        prev_year = d_from.year - 1
        return date(prev_year, 1, 1), date(prev_year, 12, 31)

    last_dom = calendar.monthrange(d_to.year, d_to.month)[1]
    if d_from.year == d_to.year and d_from.month == d_to.month and d_from.day == 1 and d_to.day == last_dom:
        if d_from.month == 1:
            p_year, p_month = d_from.year - 1, 12
        else:
            p_year, p_month = d_from.year, d_from.month - 1
        p_last = calendar.monthrange(p_year, p_month)[1]
        return date(p_year, p_month, 1), date(p_year, p_month, p_last)

    span_days = (d_to - d_from).days + 1
    prev_to = d_from - timedelta(days=1)
    prev_from = prev_to - timedelta(days=span_days - 1)
    return prev_from, prev_to


def _pct_delta(current: float, previous: float | None) -> float | None:
    if previous is None or previous <= 0:
        return None
    return round(((current - previous) / previous) * 100.0, 2)


def _format_period_label(period: str, group_by: str) -> str:
    if group_by == "month" and len(period) == 7:
        try:
            yr, mo = period.split("-")
            m_idx = int(mo)
            if 1 <= m_idx <= 12:
                return f"{_MONTH_NAMES_ES[m_idx]} {yr}"
        except Exception:
            pass
    if group_by == "day" and len(period) == 10:
        try:
            return f"{period[8:10]}/{period[5:7]}"
        except Exception:
            pass
    return period


async def get_compras_analytics(
    db: AsyncSession,
    group_by: str = "year",
    date_from: str | None = None,
    date_to: str | None = None,
) -> Dict[str, Any]:
    """
    Calcula KPIs ejecutivos y serie temporal agrupada (`year`, `month`, `day`)
    en una sola pasada sobre índices de cobertura SQLite.
    """
    norm_group = (group_by or "year").strip().lower()
    if norm_group not in ("year", "month", "day"):
        norm_group = "year"

    substr_len = {"year": 4, "month": 7, "day": 10}[norm_group]
    where_sql, params, d_from, d_to = _build_date_where(date_from, date_to, col="fecha")

    bounds_row = (
        await db.execute(
            text("SELECT (SELECT MIN(fecha) FROM compras), (SELECT MAX(fecha) FROM compras)")
        )
    ).fetchone()
    min_date_str = str(bounds_row[0])[:10] if bounds_row and bounds_row[0] else None
    max_date_str = str(bounds_row[1])[:10] if bounds_row and bounds_row[1] else None

    # En modo mensual con rango completo de años/meses aprovechamos el índice de expresión ym_cov
    series_where = where_sql
    series_params = dict(params)
    if norm_group == "month" and d_from is not None and d_to is not None and d_from.day == 1:
        last_dom = calendar.monthrange(d_to.year, d_to.month)[1]
        if d_to.day == last_dom:
            series_where = " WHERE substr(fecha, 1, 7) >= :ym_from AND substr(fecha, 1, 7) <= :ym_to"
            series_params = {
                "ym_from": d_from.strftime("%Y-%m"),
                "ym_to": d_to.strftime("%Y-%m"),
            }

    series_sql = text(
        f"""
        SELECT
            substr(fecha, 1, :sub_len) AS period,
            COALESCE(SUM(precio_total), 0.0) AS total_amount,
            COUNT(DISTINCT factura) AS invoice_count,
            COUNT(*) AS line_count,
            COALESCE(SUM(COALESCE(cant_fact, cant_entr, cant_ped, 0)), 0) AS total_units
        FROM compras
        {series_where}
        GROUP BY substr(fecha, 1, :sub_len)
        ORDER BY period ASC
        """
    )
    series_params["sub_len"] = substr_len
    series_rows = (await db.execute(series_sql, series_params)).fetchall()

    series: List[Dict[str, Any]] = []
    total_amount = 0.0
    invoice_count = 0
    line_count = 0
    total_units = 0

    for row in series_rows:
        p_key = str(row[0] or "")
        s_amount = round(float(row[1] or 0.0), 2)
        s_invoices = int(row[2] or 0)
        s_lines = int(row[3] or 0)
        s_units = int(row[4] or 0)
        total_amount += s_amount
        invoice_count += s_invoices
        line_count += s_lines
        total_units += s_units
        series.append(
            {
                "period": p_key,
                "label": _format_period_label(p_key, norm_group),
                "total_amount": s_amount,
                "invoice_count": s_invoices,
                "line_count": s_lines,
                "total_units": s_units,
                "avg_ticket": round(s_amount / s_invoices, 2) if s_invoices > 0 else 0.0,
            }
        )

    total_amount = round(total_amount, 2)
    avg_ticket = round(total_amount / invoice_count, 2) if invoice_count > 0 else 0.0

    deltas: Dict[str, float | None] = {
        "total_amount_pct": None,
        "invoice_count_pct": None,
        "avg_ticket_pct": None,
        "total_units_pct": None,
    }
    previous_period: Dict[str, Any] | None = None

    if d_from is not None and d_to is not None:
        prev_from, prev_to = _compute_previous_period(d_from, d_to)
        prev_params = {
            "d_from": f"{prev_from.isoformat()} 00:00:00",
            "d_to": f"{prev_to.isoformat()} 23:59:59.999999",
        }
        prev_sql = text(
            """
            SELECT
                COALESCE(SUM(precio_total), 0.0) AS total_amount,
                COUNT(DISTINCT factura) AS invoice_count,
                COALESCE(SUM(COALESCE(cant_fact, cant_entr, cant_ped, 0)), 0) AS total_units
            FROM compras
            WHERE fecha >= :d_from AND fecha <= :d_to
            """
        )
        prev_row = (await db.execute(prev_sql, prev_params)).fetchone()
        if prev_row and int(prev_row[1] or 0) > 0:
            p_amount = round(float(prev_row[0] or 0.0), 2)
            p_invoices = int(prev_row[1] or 0)
            p_units = int(prev_row[2] or 0)
            p_ticket = round(p_amount / p_invoices, 2) if p_invoices > 0 else 0.0
            deltas = {
                "total_amount_pct": _pct_delta(total_amount, p_amount),
                "invoice_count_pct": _pct_delta(float(invoice_count), float(p_invoices)),
                "avg_ticket_pct": _pct_delta(avg_ticket, p_ticket),
                "total_units_pct": _pct_delta(float(total_units), float(p_units)),
            }
            previous_period = {
                "date_from": prev_from.isoformat(),
                "date_to": prev_to.isoformat(),
                "total_amount": p_amount,
                "invoice_count": p_invoices,
                "avg_ticket": p_ticket,
                "total_units": p_units,
            }

    return {
        "group_by": norm_group,
        "date_from": d_from.isoformat() if d_from else None,
        "date_to": d_to.isoformat() if d_to else None,
        "bounds": {
            "min_date": min_date_str,
            "max_date": max_date_str,
        },
        "kpis": {
            "total_amount": total_amount,
            "invoice_count": invoice_count,
            "line_count": line_count,
            "avg_ticket": avg_ticket,
            "total_units": total_units,
            "deltas": deltas,
        },
        "previous_period": previous_period,
        "series": series,
    }


async def get_productos_analytics(
    db: AsyncSession,
    mode: str = "last_purchase",
    search: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = 1,
    page_size: int = 20,
) -> Dict[str, Any]:
    """
    Explorador paginado de productos comprados:
    - `last_purchase`: ordenados por fecha de compra más reciente (`MAX(fecha)`).
    - `most_purchased`: ranking por unidades totales y frecuencia dentro del rango de fechas.
    """
    norm_mode = (mode or "last_purchase").strip().lower()
    if norm_mode not in ("last_purchase", "most_purchased"):
        norm_mode = "last_purchase"

    safe_page = max(1, int(page or 1))
    safe_size = max(1, min(int(page_size or 20), 100))
    offset = (safe_page - 1) * safe_size

    _, date_params, d_from, d_to = _build_date_where(date_from, date_to, col="c.fecha")
    c_clauses: list[str] = []
    params: dict[str, Any] = {}
    if "d_from" in date_params:
        c_clauses.append("c.fecha >= :d_from")
        params["d_from"] = date_params["d_from"]
    if "d_to" in date_params:
        c_clauses.append("c.fecha <= :d_to")
        params["d_to"] = date_params["d_to"]

    p_clauses: list[str] = []
    cleaned_search = (search or "").strip()
    if cleaned_search:
        params["search_like"] = f"%{cleaned_search.upper()}%"
        if cleaned_search.isdigit():
            params["code_like"] = f"%{cleaned_search}%"
            p_clauses.append("(UPPER(p.nombre) LIKE :search_like OR CAST(p.codigo AS TEXT) LIKE :code_like)")
        else:
            p_clauses.append(
                "(UPPER(p.nombre) LIKE :search_like OR UPPER(COALESCE(p.droga, '')) LIKE :search_like OR UPPER(COALESCE(p.laboratorio, '')) LIKE :search_like)"
            )

    c_date_sub_clauses: list[str] = []
    if "d_from" in date_params:
        c_date_sub_clauses.append("c2.fecha >= :d_from")
    if "d_to" in date_params:
        c_date_sub_clauses.append("c2.fecha <= :d_to")
    sub_date_sql = (" AND " + " AND ".join(c_date_sub_clauses)) if c_date_sub_clauses else ""

    if not p_clauses and not c_clauses:
        total = int((await db.execute(text("SELECT COUNT(*) FROM productos_comprados"))).scalar() or 0)
        join_in_cte = ""
        where_sql = ""
    else:
        join_in_cte = "JOIN productos p ON p.id = c.producto_id" if p_clauses else ""
        where_parts = c_clauses + p_clauses
        where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
        count_sql = text(
            f"""
            SELECT COUNT(*) FROM (
                SELECT c.producto_id
                FROM compras c
                {join_in_cte}
                {where_sql}
                GROUP BY c.producto_id
            ) sub
            """
        )
        total = int((await db.execute(count_sql, params)).scalar() or 0)

    total_pages = max(1, (total + safe_size - 1) // safe_size) if total > 0 else 1
    if safe_page > total_pages:
        safe_page = total_pages
        offset = (safe_page - 1) * safe_size

    order_clause = (
        "last_fecha DESC, total_units DESC"
        if norm_mode == "last_purchase"
        else "total_units DESC, purchase_count DESC, last_fecha DESC"
    )

    max_units = 0
    if norm_mode == "most_purchased" and total > 0:
        if safe_page > 1:
            max_sql = text(
                f"""
                SELECT SUM(COALESCE(c.cant_fact, c.cant_entr, c.cant_ped, 0)) AS u_sum
                FROM compras c
                {join_in_cte}
                {where_sql}
                GROUP BY c.producto_id
                ORDER BY u_sum DESC
                LIMIT 1
                """
            )
            max_units = int((await db.execute(max_sql, params)).scalar() or 0)

    list_sql = text(
        f"""
        WITH ranked AS (
            SELECT
                c.producto_id AS producto_id,
                MAX(c.fecha) AS last_fecha,
                SUM(COALESCE(c.cant_fact, c.cant_entr, c.cant_ped, 0)) AS total_units,
                COUNT(*) AS purchase_count,
                COALESCE(SUM(c.precio_total), 0.0) AS total_spent
            FROM compras c
            {join_in_cte}
            {where_sql}
            GROUP BY c.producto_id
            ORDER BY {order_clause}
            LIMIT :limit OFFSET :offset
        )
        SELECT
            p.id,
            p.codigo,
            p.nombre,
            p.droga,
            p.laboratorio,
            p.presentacion,
            r.last_fecha,
            r.total_units,
            r.purchase_count,
            r.total_spent,
            (
                SELECT c2.precio_unitario
                FROM compras c2
                WHERE c2.producto_id = r.producto_id {sub_date_sql}
                ORDER BY c2.fecha DESC
                LIMIT 1
            ) AS last_price
        FROM ranked r
        JOIN productos p ON p.id = r.producto_id
        ORDER BY {order_clause}
        """
    )
    list_params = dict(params)
    list_params["limit"] = safe_size
    list_params["offset"] = offset
    rows = (await db.execute(list_sql, list_params)).fetchall()

    items: List[Dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "producto_id": int(row[0]),
                "codigo": str(row[1]),
                "nombre": str(row[2] or ""),
                "droga": str(row[3] or ""),
                "laboratorio": str(row[4] or ""),
                "presentacion": str(row[5] or ""),
                "last_fecha": str(row[6] or ""),
                "total_units": int(row[7] or 0),
                "purchase_count": int(row[8] or 0),
                "total_spent": round(float(row[9] or 0.0), 2),
                "last_price": round(float(row[10] or 0.0), 2),
            }
        )

    if norm_mode == "most_purchased" and safe_page == 1 and items:
        max_units = items[0]["total_units"]

    return {
        "mode": norm_mode,
        "search": cleaned_search or None,
        "date_from": d_from.isoformat() if d_from else None,
        "date_to": d_to.isoformat() if d_to else None,
        "page": safe_page,
        "page_size": safe_size,
        "total": total,
        "total_pages": total_pages,
        "max_units": max_units,
        "items": items,
    }


def _normalize_drug_term(raw: str | None) -> str:
    if not raw:
        return ""
    return re.sub(r"\s+", " ", str(raw).strip().upper())


async def get_drogas_comparison(
    db: AsyncSession,
    droga: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> Dict[str, Any]:
    """
    Buscador de drogas / principios activos y comparador de precios por marca/laboratorio
    ordenado de menor a mayor último precio registrado.
    """
    norm_q = _normalize_drug_term(q)
    norm_droga = _normalize_drug_term(droga)

    if norm_q:
        sugg_sql = text(
            """
            SELECT
                UPPER(TRIM(p.droga)) AS droga_norm,
                COUNT(DISTINCT p.id) AS product_count,
                COUNT(DISTINCT p.laboratorio) AS lab_count
            FROM productos p
            JOIN productos_comprados pc ON pc.id = p.id
            WHERE p.droga IS NOT NULL
              AND TRIM(p.droga) != ''
              AND UPPER(TRIM(p.droga)) LIKE :q_like
            GROUP BY UPPER(TRIM(p.droga))
            ORDER BY
                CASE WHEN UPPER(TRIM(p.droga)) LIKE :q_prefix THEN 0 ELSE 1 END,
                lab_count DESC,
                product_count DESC
            LIMIT 20
            """
        )
        sugg_rows = (
            await db.execute(
                sugg_sql,
                {"q_like": f"%{norm_q}%", "q_prefix": f"{norm_q}%"},
            )
        ).fetchall()
    else:
        sugg_sql = text(
            """
            SELECT
                UPPER(TRIM(p.droga)) AS droga_norm,
                COUNT(DISTINCT p.id) AS product_count,
                COUNT(DISTINCT p.laboratorio) AS lab_count
            FROM productos p
            JOIN productos_comprados pc ON pc.id = p.id
            WHERE p.droga IS NOT NULL
              AND TRIM(p.droga) != ''
              AND UPPER(TRIM(p.droga)) NOT IN ('PRODUCTO COSMÉTICO', 'ACCESORIO', 'COSMETICA', 'PERFUMERIA')
            GROUP BY UPPER(TRIM(p.droga))
            HAVING lab_count >= 2
            ORDER BY lab_count DESC, product_count DESC
            LIMIT 16
            """
        )
        sugg_rows = (await db.execute(sugg_sql)).fetchall()

    suggestions = [
        {
            "droga": str(r[0]),
            "product_count": int(r[1] or 0),
            "lab_count": int(r[2] or 0),
        }
        for r in sugg_rows
    ]

    if not norm_droga:
        return {
            "droga": None,
            "q": norm_q or None,
            "date_from": None,
            "date_to": None,
            "cheapest_price": None,
            "suggestions": suggestions,
            "items": [],
        }

    _, date_params, d_from, d_to = _build_date_where(date_from, date_to, col="c.fecha")
    date_clauses: list[str] = []
    sub_date_clauses: list[str] = []
    if "d_from" in date_params:
        date_clauses.append("c.fecha >= :d_from")
        sub_date_clauses.append("c2.fecha >= :d_from")
    if "d_to" in date_params:
        date_clauses.append("c.fecha <= :d_to")
        sub_date_clauses.append("c2.fecha <= :d_to")
    c_date_sql = (" AND " + " AND ".join(date_clauses)) if date_clauses else ""
    sub_date_sql = (" AND " + " AND ".join(sub_date_clauses)) if sub_date_clauses else ""

    async def _run_compare(match_clause: str, match_params: dict[str, Any]) -> list[Any]:
        sql = text(
            f"""
            WITH agg AS (
                SELECT
                    c.producto_id AS producto_id,
                    MIN(c.precio_unitario) AS min_price,
                    MAX(c.precio_unitario) AS max_price,
                    MAX(c.fecha) AS last_fecha,
                    COUNT(*) AS purchase_count,
                    SUM(COALESCE(c.cant_fact, c.cant_entr, c.cant_ped, 0)) AS total_units
                FROM compras c
                JOIN productos p ON p.id = c.producto_id
                WHERE {match_clause} {c_date_sql}
                GROUP BY c.producto_id
            )
            SELECT
                p.id,
                p.codigo,
                p.nombre,
                p.droga,
                p.presentacion,
                p.laboratorio,
                (
                    SELECT c2.precio_unitario
                    FROM compras c2
                    WHERE c2.producto_id = a.producto_id {sub_date_sql}
                    ORDER BY c2.fecha DESC
                    LIMIT 1
                ) AS last_price,
                a.min_price,
                a.max_price,
                a.last_fecha,
                a.purchase_count,
                a.total_units
            FROM agg a
            JOIN productos p ON p.id = a.producto_id
            ORDER BY last_price ASC, a.last_fecha DESC
            """
        )
        merged_params = {**date_params, **match_params}
        return list((await db.execute(sql, merged_params)).fetchall())

    rows = await _run_compare("UPPER(TRIM(p.droga)) = :droga_exact", {"droga_exact": norm_droga})
    if not rows:
        rows = await _run_compare(
            "(UPPER(TRIM(COALESCE(p.droga, ''))) LIKE :droga_like OR UPPER(p.nombre) LIKE :droga_like)",
            {"droga_like": f"%{norm_droga}%"},
        )

    valid_prices = [float(r[6]) for r in rows if r[6] is not None and float(r[6]) > 0]
    cheapest_price = round(min(valid_prices), 2) if valid_prices else None

    items: List[Dict[str, Any]] = []
    for r in rows:
        last_price = round(float(r[6] or 0.0), 2)
        min_price = round(float(r[7] or 0.0), 2)
        max_price = round(float(r[8] or 0.0), 2)
        is_cheapest = bool(cheapest_price is not None and last_price > 0 and abs(last_price - cheapest_price) < 0.01)
        if cheapest_price and cheapest_price > 0 and last_price > 0:
            diff_pct = round(((last_price - cheapest_price) / cheapest_price) * 100.0, 2)
        else:
            diff_pct = 0.0

        items.append(
            {
                "producto_id": int(r[0]),
                "codigo": str(r[1]),
                "nombre": str(r[2] or ""),
                "droga": str(r[3] or ""),
                "presentacion": str(r[4] or ""),
                "laboratorio": str(r[5] or ""),
                "last_price": last_price,
                "min_price": min_price,
                "max_price": max_price,
                "last_fecha": str(r[9] or ""),
                "purchase_count": int(r[10] or 0),
                "total_units": int(r[11] or 0),
                "is_cheapest": is_cheapest,
                "diff_pct": max(0.0, diff_pct),
            }
        )

    return {
        "droga": norm_droga,
        "q": norm_q or None,
        "date_from": d_from.isoformat() if d_from else None,
        "date_to": d_to.isoformat() if d_to else None,
        "cheapest_price": cheapest_price,
        "suggestions": suggestions,
        "items": items,
    }
