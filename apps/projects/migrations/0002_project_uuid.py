import uuid

from django.db import migrations, models


def populate_project_uuids(apps, schema_editor):
    Project = apps.get_model("projects", "Project")
    for project in Project.objects.all().only("pk"):
        Project.objects.filter(pk=project.pk).update(uuid=uuid.uuid4())


class Migration(migrations.Migration):

    dependencies = [
        ("projects", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="project",
            name="uuid",
            field=models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, null=True),
        ),
        migrations.RunPython(populate_project_uuids, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="project",
            name="uuid",
            field=models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, unique=True),
        ),
    ]
