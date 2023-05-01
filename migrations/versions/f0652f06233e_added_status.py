"""added status

Revision ID: f0652f06233e
Revises: 72ad1395da87
Create Date: 2023-05-01 21:37:33.871941

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f0652f06233e'
down_revision = '72ad1395da87'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('admin_signup', schema=None) as batch_op:
        batch_op.add_column(sa.Column('name', sa.String(length=20), nullable=False))

    with op.batch_alter_table('reservation', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status', sa.Integer(), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('reservation', schema=None) as batch_op:
        batch_op.drop_column('status')

    with op.batch_alter_table('admin_signup', schema=None) as batch_op:
        batch_op.drop_column('name')

    # ### end Alembic commands ###
