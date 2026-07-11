from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0002_user_activity_log"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="runtime_protection_enabled",
            field=models.BooleanField(
                default=False,
                help_text="Enable in-path EEG Gateway blocking and server-side trace scoring enforcement.",
            ),
        ),
    ]
