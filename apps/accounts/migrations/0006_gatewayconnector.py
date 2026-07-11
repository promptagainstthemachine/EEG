# Generated manually for GatewayConnector

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0005_alter_user_dashboard_project_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="GatewayConnector",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("label", models.CharField(max_length=120)),
                ("status", models.CharField(db_index=True, default="active", max_length=32)),
                ("config", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="gateway_connectors",
                        to="accounts.organization",
                    ),
                ),
            ],
            options={
                "verbose_name": "Gateway Connector",
                "verbose_name_plural": "Gateway Connectors",
                "ordering": ["-updated_at", "-id"],
            },
        ),
    ]
