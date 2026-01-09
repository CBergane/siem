from django.core.management.base import BaseCommand

from apps.logs.tasks import prune_inventory_snapshots


class Command(BaseCommand):
    help = "Delete inventory snapshots older than a given number of days."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=30,
            help="Delete snapshots older than this many days (default: 30).",
        )

    def handle(self, *args, **options):
        days = options["days"]
        deleted = prune_inventory_snapshots(days=days)
        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted} inventory snapshots."))
