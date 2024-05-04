# Generated by Django 5.0.2 on 2024-04-17 05:48

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0002_rename_feature_features'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Feedback',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('overall_experience', models.CharField(blank=True, max_length=255, verbose_name='Overall Experience')),
                ('easy_to_find_info', models.CharField(blank=True, max_length=255, verbose_name='Easy to Find Info')),
                ('navigation', models.CharField(blank=True, max_length=255, verbose_name='Navigation')),
                ('issues', models.CharField(blank=True, max_length=255, verbose_name='Issues')),
                ('liked_most', models.CharField(blank=True, max_length=255, verbose_name='Liked Most')),
                ('improvements', models.CharField(blank=True, max_length=255, verbose_name='Improvements')),
                ('likelihood_to_recommend', models.IntegerField(blank=True, null=True, verbose_name='Likelihood to Recommend')),
                ('additional_feedback', models.TextField(blank=True, verbose_name='Additional Feedback')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Feedback',
                'verbose_name_plural': 'Feedbacks',
            },
        ),
        migrations.DeleteModel(
            name='features',
        ),
    ]