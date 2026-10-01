import sqlite3


def log_action(conn: sqlite3.Connection, team_id: int, user, action: str, target: str = "", detail: str = "", ip: str = ""):
    conn.execute(
        "INSERT INTO audit_log (team_id, user_id, user_name, action, target, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (team_id, user["id"] if user else None, user["name"] if user else "system", action, target, detail, ip),
    )


def notify_team(conn: sqlite3.Connection, team_id: int, message: str, exclude_user_id: int | None = None):
    rows = conn.execute("SELECT id FROM users WHERE team_id = ?", (team_id,)).fetchall()
    for row in rows:
        if exclude_user_id is not None and row["id"] == exclude_user_id:
            continue
        conn.execute(
            "INSERT INTO notifications (team_id, user_id, message) VALUES (?, ?, ?)",
            (team_id, row["id"], message),
        )
