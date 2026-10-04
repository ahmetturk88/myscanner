import uuid

from extensions import db
from models.async_scan_task import AsyncScanTask


def enqueue_owned_task(task, args, user_id):
    """Persist ownership before publishing the task to the broker."""
    task_id = str(uuid.uuid4())
    ownership = AsyncScanTask(task_id=task_id, user_id=user_id)
    db.session.add(ownership)
    db.session.commit()
    try:
        task.apply_async(args=args, task_id=task_id)
    except Exception:
        db.session.delete(ownership)
        db.session.commit()
        raise
    return task_id
