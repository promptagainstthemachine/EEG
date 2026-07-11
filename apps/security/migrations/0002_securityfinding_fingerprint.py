# Generated manually for finding deduplication

import hashlib

from django.db import migrations, models


def _fp(rule_id: str, file_path: str, line_number) -> str:
    fpath = (file_path or "").strip().replace("\\", "/").lstrip("/")
    line_key = 0 if line_number is None else int(line_number)
    raw = f"{(rule_id or 'unknown').strip()}|{fpath}|{line_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def backfill_and_dedupe(apps, schema_editor):
    SecurityFinding = apps.get_model("security", "SecurityFinding")
    seen_keys: dict[tuple, object] = {}
    for row in SecurityFinding.objects.order_by("first_seen_at").iterator():
        fp = _fp(row.rule_id, row.file_path, row.line_number)
        key = (row.organization_id, row.project_id, fp)
        if key in seen_keys:
            row.delete()
            continue
        seen_keys[key] = row.pk
        if row.fingerprint != fp:
            row.fingerprint = fp
            row.save(update_fields=["fingerprint"])


class Migration(migrations.Migration):

    dependencies = [
        ("security", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="securityfinding",
            name="fingerprint",
            field=models.CharField(blank=True, db_index=True, max_length=64),
        ),
        migrations.RunPython(backfill_and_dedupe, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="securityfinding",
            constraint=models.UniqueConstraint(
                fields=("organization", "project", "fingerprint"),
                name="uniq_security_finding_per_project",
            ),
        ),
    ]
