from celery import Celery

# Configure Celery to use Redis as the message broker
celery = Celery(
    "worker",  # This is the name of your Celery application
    broker="redis://localhost:6379/0",  # This is the Redis connection string
    backend="redis://localhost:6379/0",  # Optional, for storing task results
)

# Auto-discover tasks from the specified modules
celery.autodiscover_tasks(["insightly_api.tasks"])


if __name__ == "__main__":
    celery.start()
