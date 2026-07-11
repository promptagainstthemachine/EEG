from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0003_organization_runtime_protection"),
        ("projects", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="dashboard_project",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="dashboard_focus_users",
                to="projects.project",
            ),
        ),
    ]
