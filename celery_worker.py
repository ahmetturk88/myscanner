"""Validated worker/Beat entry point, without importing Flask or touching its DB."""
from celery_app import celery, require_broker
require_broker(celery)
