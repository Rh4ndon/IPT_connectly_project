# Generated by Django 5.1.5 on 2025-02-13 14:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('posts', '0007_post_metadata_post_post_type_post_title'),
    ]

    operations = [
        migrations.AddField(
            model_name='post',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AlterField(
            model_name='post',
            name='metadata',
            field=models.JSONField(default=dict),
        ),
    ]
