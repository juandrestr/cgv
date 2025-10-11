"""recreated head to match DB state

Revision ID: a0895bd66fca
Revises: 1c6efb76704b
Create Date: 2025-10-11 09:45:42
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "a0895bd66fca"
down_revision: Union[str, None] = "1c6efb76704b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # DB already at this state; no-op.
    pass

def downgrade() -> None:
    # No-op (this is only to align code with current DB head).
    pass
