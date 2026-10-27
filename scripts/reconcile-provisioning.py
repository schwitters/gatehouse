"""Inspect or reconcile interrupted provisioning while the service is stopped."""
import argparse
import getpass
import json
import sqlite3
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database")
    parser.add_argument("invite_id")
    parser.add_argument("--service-stopped", action="store_true")
    parser.add_argument("--confirmed", choices=(
        "principal-absent", "principal-created", "activation-pending", "activated"))
    args = parser.parse_args()
    # mode=rw prevents accidentally creating a new database on a mistyped path.
    from pathlib import Path
    database = Path(args.database).resolve().as_uri() + "?mode=rw"
    with sqlite3.connect(database, uri=True, timeout=5) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("""SELECT invite_id, tenant_id, uid, stage, updated_at
                            FROM provisioning_job WHERE invite_id=?""", (args.invite_id,)).fetchone()
        if row is None:
            parser.error("No provisioning job exists for that invitation")
        if not args.confirmed:
            print(json.dumps(dict(row), indent=2))
            return
        if not args.service_stopped:
            parser.error("Stop Gatehouse and pass --service-stopped before changing state")
        expected, destination = {
            "principal-absent": (1, 0), "principal-created": (1, 2),
            "activation-pending": (3, 2), "activated": (3, 4),
        }[args.confirmed]
        if row["stage"] != expected:
            parser.error("The observation does not match the current job stage")
        result = db.execute("""UPDATE provisioning_job SET stage=?, updated_at=?
                               WHERE invite_id=? AND stage=?""",
                            (destination, int(time.time()), args.invite_id, expected))
        if result.rowcount != 1:
            parser.error("The job changed concurrently")
        db.execute("""INSERT INTO provisioning_event(invite_id, stage, actor, created_at)
                      VALUES (?, ?, ?, ?)""",
                   (args.invite_id, destination, getpass.getuser(), int(time.time())))
        print(f"Reconciled {args.invite_id}: stage {expected} -> {destination}")


if __name__ == "__main__":
    main()
