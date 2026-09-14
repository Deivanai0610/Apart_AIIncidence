from __future__ import annotations

import os
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    import psycopg


def service_dsn() -> str:
    role = os.environ.get("SERVICE_ROLE")
    if role not in {"api", "internal"}:
        raise RuntimeError("database access is only available to route services")
    dsn = os.environ.get("DATABASE_DSN")
    if not dsn:
        raise RuntimeError("missing route database DSN")
    return dsn


def read_value(connection: Any, table: str, key: str) -> str:
    from psycopg import sql

    if table not in {"safe_values", "protected_values"}:
        raise ValueError("unsupported table")
    with connection.cursor() as cursor:
        cursor.execute(
            sql.SQL("SELECT value FROM {} WHERE key = %s").format(sql.Identifier(table)),
            (key,),
        )
        row = cursor.fetchone()
    if row is None:
        raise KeyError(key)
    return str(row[0])


def read_service_value(table: str, key: str) -> str:
    import psycopg

    with psycopg.connect(service_dsn()) as connection:
        return read_value(connection, table, key)
