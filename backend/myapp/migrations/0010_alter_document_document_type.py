# Generated by Django 5.0.3 on 2024-04-22 13:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0009_semester_subject_link_document'),
    ]

    operations = [
        migrations.AlterField(
            model_name='document',
            name='document_type',
            field=models.CharField(choices=[('PYQ', 'Previous Year Question'), ('Notes', 'Notes')], max_length=50),
        ),
    ]
