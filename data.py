# data.py
import os
import io
import csv
import mimetypes
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import psycopg2
import psycopg2.extras

# Load environment variables
load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME")

# ✅ Supabase DB connection
def get_conn():
    return psycopg2.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        sslmode="require"  # Supabase requires SSL
    )

# ----------------- Table creation -----------------
def create_tables():
    commands = [
        """
        CREATE TABLE IF NOT EXISTS messages (
          id SERIAL PRIMARY KEY,
          timestamp TIMESTAMP WITH TIME ZONE DEFAULT now(),
          name TEXT,
          email TEXT,
          message TEXT,
          status TEXT DEFAULT 'unread'
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS subscribers (
          id SERIAL PRIMARY KEY,
          email TEXT UNIQUE,
          timestamp TIMESTAMP WITH TIME ZONE DEFAULT now()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS blogs (
          id SERIAL PRIMARY KEY,
          timestamp TIMESTAMP WITH TIME ZONE DEFAULT now(),
          title TEXT,
          slug TEXT UNIQUE,
          content TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS files (
          id SERIAL PRIMARY KEY,
          name TEXT,
          category TEXT,
          content BYTEA,
          mimetype TEXT,
          uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
          approved BOOLEAN DEFAULT TRUE
        )
        """
    ]
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                for ddl in commands:
                    cur.execute(ddl)
        print("✅ Tables created or already exist.")
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
    finally:
        conn.close()

# ---------------- Messages ----------------
def save_message(name: str, email: str, message: str):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO messages (timestamp, name, email, message, status) VALUES (now(), %s, %s, %s, %s)",
                    (name.strip(), email.strip(), message.strip(), "unread")
                )
    finally:
        conn.close()

def load_messages():
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SELECT id, timestamp, name, email, message, status FROM messages ORDER BY id ASC")
                rows = cur.fetchall()
                return [
                    {
                        "timestamp": r["timestamp"].isoformat(timespec="seconds") if r["timestamp"] else "",
                        "name": r["name"] or "",
                        "email": r["email"] or "",
                        "message": r["message"] or "",
                        "status": r["status"] or "unread",
                        "db_id": r["id"]
                    }
                    for r in rows
                ]
    finally:
        conn.close()

def save_all_messages(msgs):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM messages")
                for m in msgs:
                    ts = m.get("timestamp") or datetime.now(timezone.utc).isoformat()
                    try:
                        t = datetime.fromisoformat(ts)
                    except Exception:
                        t = datetime.now(timezone.utc)
                    cur.execute(
                        "INSERT INTO messages (timestamp, name, email, message, status) VALUES (%s, %s, %s, %s, %s)",
                        (t, m.get("name",""), m.get("email",""), m.get("message",""), m.get("status","unread"))
                    )
    finally:
        conn.close()

def get_message_by_index(idx):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    "SELECT id, timestamp, name, email, message, status FROM messages ORDER BY id ASC OFFSET %s LIMIT 1",
                    (idx,)
                )
                r = cur.fetchone()
                if not r:
                    return None
                return {
                    "timestamp": r["timestamp"].isoformat(timespec="seconds") if r["timestamp"] else "",
                    "name": r["name"] or "",
                    "email": r["email"] or "",
                    "message": r["message"] or "",
                    "status": r["status"] or "unread",
                    "db_id": r["id"]
                }
    finally:
        conn.close()

def toggle_message_status_by_index(idx):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, status FROM messages ORDER BY id ASC OFFSET %s LIMIT 1", (idx,))
                r = cur.fetchone()
                if not r:
                    return False, None
                mid, status = r
                new = "read" if status == "unread" else "unread"
                cur.execute("UPDATE messages SET status=%s WHERE id=%s", (new, mid))
                return True, new
    finally:
        conn.close()

def delete_message_by_index(idx):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SELECT id, name FROM messages ORDER BY id ASC OFFSET %s LIMIT 1", (idx,))
                r = cur.fetchone()
                if not r:
                    return False, None
                cur.execute("DELETE FROM messages WHERE id=%s", (r["id"],))
                return True, {"name": r["name"]}
    finally:
        conn.close()

def export_messages_csv():
    msgs = load_messages()
    if not msgs:
        return None
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "name", "email", "message", "status"])
    for m in msgs:
        writer.writerow([m.get("timestamp",""), m.get("name",""), m.get("email",""), m.get("message",""), m.get("status","")])
    return buf.getvalue().encode("utf-8")

def get_messages_counts_last_n_days(days=30):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT date(timestamp) as d, count(*) FROM messages WHERE timestamp >= now() - interval %s GROUP BY d ORDER BY d",
                    (f'{days} days',)
                )
                rows = cur.fetchall()
                counts = {r[0].isoformat(): r[1] for r in rows}
                labels, values = [], []
                today = datetime.now().date()
                for i in range(days-1, -1, -1):
                    d = (today - timedelta(days=i)).isoformat()
                    labels.append(d)
                    values.append(counts.get(d, 0))
                return labels, values
    finally:
        conn.close()

# ---------------- Subscribers ----------------
def save_subscriber(email: str):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO subscribers (email, timestamp) VALUES (%s, now()) ON CONFLICT (email) DO NOTHING",
                    (email.strip().lower(),)
                )
    finally:
        conn.close()

def load_subscribers():
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SELECT id, email, timestamp FROM subscribers ORDER BY id DESC")
                return [
                    {"email": r["email"], "timestamp": r["timestamp"].isoformat(timespec="seconds") if r["timestamp"] else ""}
                    for r in cur.fetchall()
                ]
    finally:
        conn.close()

# ---------------- Blogs ----------------
def slugify(text: str) -> str:
    import re
    s = (text or "").lower().strip()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[-\s]+", "-", s)
    return s[:200]

def add_blog(title, content):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT MAX(id) FROM blogs")
                r = cur.fetchone()
                nid = (r[0] or 0) + 1
                slug = slugify(title) or f"post-{nid}"
                cur.execute(
                    "INSERT INTO blogs (timestamp, title, slug, content) VALUES (now(), %s, %s, %s)",
                    (title.strip(), slug, content.strip())
                )
                return {"id": nid, "timestamp": datetime.now().isoformat(timespec="seconds"), "title": title, "slug": slug, "content": content}
    finally:
        conn.close()

def load_blogs():
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SELECT id, timestamp, title, slug, content FROM blogs ORDER BY id DESC")
                return [
                    {
                        "id": r["id"],
                        "timestamp": r["timestamp"].isoformat(timespec="seconds") if r["timestamp"] else "",
                        "title": r["title"],
                        "slug": r["slug"],
                        "content": r["content"]
                    }
                    for r in cur.fetchall()
                ]
    finally:
        conn.close()

def get_blog_by_slug(slug):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SELECT id, timestamp, title, slug, content FROM blogs WHERE slug=%s LIMIT 1", (slug,))
                r = cur.fetchone()
                if not r:
                    return None
                return {"id": r["id"], "timestamp": r["timestamp"].isoformat(timespec="seconds") if r["timestamp"] else "", "title": r["title"], "slug": r["slug"], "content": r["content"]}
    finally:
        conn.close()

def delete_blog_by_id(bid):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM blogs WHERE id = %s", (bid,))
    finally:
        conn.close()

# ---------------- Files ----------------
def _guess_mimetype(filename, file_storage=None):
    if file_storage and getattr(file_storage, "mimetype", None):
        return file_storage.mimetype
    mt = mimetypes.guess_type(filename)[0]
    return mt or "application/octet-stream"

def save_file_from_storage(category, file_storage, rename_to=None, approve=True, single_replace=False):
    if not file_storage or file_storage.filename == "":
        return None, "No file provided."
    original = secure_filename(file_storage.filename)
    fname = secure_filename(rename_to) if rename_to else (datetime.now().strftime("%Y%m%d_%H%M%S_") + original)
    try:
        content = file_storage.read()
        mimetype = _guess_mimetype(fname, file_storage)
        conn = get_conn()
        with conn:
            with conn.cursor() as cur:
                if single_replace:
                    cur.execute("DELETE FROM files WHERE category = %s", (category,))
                cur.execute(
                    "INSERT INTO files (name, category, content, mimetype, uploaded_at, approved) VALUES (%s, %s, %s, %s, now(), %s) RETURNING id",
                    (fname, category, psycopg2.Binary(content), mimetype, approve)
                )
        return fname, None
    except Exception as e:
        return None, str(e)

def get_file_record(category, name, approved=None):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                if approved is None:
                    cur.execute(
                        "SELECT id, name, content, mimetype, uploaded_at, approved FROM files WHERE category=%s AND name=%s ORDER BY uploaded_at DESC LIMIT 1",
                        (category, name)
                    )
                else:
                    cur.execute(
                        "SELECT id, name, content, mimetype, uploaded_at, approved FROM files WHERE category=%s AND name=%s AND approved=%s ORDER BY uploaded_at DESC LIMIT 1",
                        (category, name, approved)
                    )
                r = cur.fetchone()
                if not r:
                    return None
                return {"id": r["id"], "name": r["name"], "content": bytes(r["content"]) if r["content"] else b"", "mimetype": r["mimetype"], "uploaded_at": r["uploaded_at"], "approved": r["approved"]}
    finally:
        conn.close()

def get_latest_file_record(category, only_images=False):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                if only_images:
                    cur.execute(
                        "SELECT id, name, content, mimetype, uploaded_at FROM files WHERE category=%s AND mimetype LIKE 'image/%%' ORDER BY uploaded_at DESC LIMIT 1",
                        (category,)
                    )
                else:
                    cur.execute(
                        "SELECT id, name, content, mimetype, uploaded_at FROM files WHERE category=%s ORDER BY uploaded_at DESC LIMIT 1",
                        (category,)
                    )
                r = cur.fetchone()
                if not r:
                    return None
                return {"id": r["id"], "name": r["name"], "content": bytes(r["content"]) if r["content"] else b"", "mimetype": r["mimetype"], "uploaded_at": r["uploaded_at"]}
    finally:
        conn.close()

def get_latest_filename(category):
    rec = get_latest_file_record(category)
    return rec["name"] if rec else None

def get_file_timestamp(category, filename):
    rec = get_file_record(category, filename)
    if not rec:
        return None
    dt = rec.get("uploaded_at")
    return dt.timestamp() if dt else None

def list_gallery_media():
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SELECT name, mimetype, uploaded_at FROM files WHERE category='gallery' ORDER BY uploaded_at DESC")
                rows = cur.fetchall()
                out = []
                for r in rows:
                    typ = "image" if (r["mimetype"] or "").startswith("image") else "video" if (r["mimetype"] or "").startswith("video") else "other"
                    out.append({"name": r["name"], "type": typ, "url": f"/media/gallery/{r['name']}"})
                return out
    finally:
        conn.close()

def list_projects(approved=True):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT name FROM files WHERE category='project' AND approved=%s ORDER BY uploaded_at DESC",
                    (approved,)
                )
                return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()

def approve_project_by_name(name):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE files SET approved = TRUE WHERE category='project' AND name=%s AND approved=FALSE RETURNING id",
                    (name,)
                )
                return bool(cur.fetchone())
    finally:
        conn.close()

def reject_project_by_name(name):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM files WHERE category='project' AND name=%s AND approved=FALSE RETURNING id",
                    (name,)
                )
                return bool(cur.fetchone())
    finally:
        conn.close()

def delete_project_by_name(name):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM files WHERE category='project' AND name=%s RETURNING id",
                    (name,)
                )
                return bool(cur.fetchone())
    finally:
        conn.close()

def delete_file(category, name):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM files WHERE category=%s AND name=%s RETURNING id",
                    (category, name)
                )
                return bool(cur.fetchone())
    finally:
        conn.close()

# ---------------- Auto-create tables ----------------
try:
    create_tables()
except Exception as e:
    print("⚠️ Could not auto-create tables:", e)
