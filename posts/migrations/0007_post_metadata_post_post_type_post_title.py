# Generated by Django 5.1.5 on 2025-02-13 14:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('posts', '0006_alter_post_author_alter_comment_author_delete_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='post',
            name='metadata',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='post',
            name='post_type',
            field=models.CharField(choices=[('text', 'Text'), ('image', 'Image'), ('video', 'Video')], default='text', max_length=10),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='post',
            name='title',
            field=models.CharField(default='sample titles', max_length=255),
            preserve_default=False,
        ),
    ]
