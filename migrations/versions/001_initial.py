"""Initial RedForge schema, frozen independently of later ORM changes."""

import sqlalchemy as sa
from alembic import op

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    tables = {"engagements", "scans", "findings", "audit_logs"}
    if tables.issubset(existing):
        return  # A local CLI run may have initialized the schema already.
    if existing & tables:
        raise RuntimeError("partial RedForge schema exists; resolve it before migration")

    op.create_table(
        "engagements",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column("client", sa.String(200), nullable=False),
        sa.Column("operator", sa.String(200), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(100), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("profile", sa.String(30), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("tool_status", sa.JSON(), nullable=False),
    )
    op.create_index("ix_scans_engagement_id", "scans", ["engagement_id"])
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("engagement_id", sa.String(100), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("asset", sa.String(500), nullable=False),
        sa.Column("location", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(20), nullable=False),
        sa.Column("verification", sa.String(30), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("first_detected", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_detected", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_engagement_id", "findings", ["engagement_id"])
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("engagement_id", sa.String(100)),
        sa.Column("details", sa.JSON(), nullable=False),
    )


def downgrade():
    op.drop_table("audit_logs")
    op.drop_index("ix_findings_fingerprint", "findings")
    op.drop_index("ix_findings_engagement_id", "findings")
    op.drop_index("ix_findings_scan_id", "findings")
    op.drop_table("findings")
    op.drop_index("ix_scans_engagement_id", "scans")
    op.drop_table("scans")
    op.drop_table("engagements")
