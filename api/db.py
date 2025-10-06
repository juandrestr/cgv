import os
import psycopg
from psycopg.rows import dict_row

PG_DSN = os.getenv(
    "DATABASE_URL",
    "dbname=cgv user=cgv password=cgv host=db port=5432"
)

def get_conn():
    return psycopg.connect(PG_DSN, row_factory=dict_row)
