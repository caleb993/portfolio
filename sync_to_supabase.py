import os
from supabase import create_client

# 🔑 Your Supabase project details
PROJECT_URL = "https://otxksqyjllidcsgyreve.supabase.co"
SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im90eGtzcXlqbGxpZGNzZ3lyZXZlIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NzMzOTQ1OCwiZXhwIjoyMDcyOTE1NDU4fQ.ScMs3WxJd5V02u5JOBEySW9u9hdCOrrrFsxiyhhOgQY"

# 📂 Your local root folder
LOCAL_ROOT = r"C:\Users\PC\Desktop\PORTFOLIO"

# Initialize Supabase client
supabase = create_client(PROJECT_URL, SERVICE_ROLE_KEY)

def should_skip(file_name):
    """Skip .gitkeep, hidden files, and system junk files."""
    return file_name.startswith(".") or file_name.lower() in ["thumbs.db", ".ds_store"]

def upload_folder(bucket_name, local_path, remote_path=""):
    """
    Recursively uploads a local folder (with nested files) to a Supabase Storage bucket.
    Skips .gitkeep and hidden/system files.
    """
    uploaded_files = []
    for root, _, files in os.walk(local_path):
        for file in files:
            if should_skip(file):
                print(f"⏭️ Skipped: {file}")
                continue

            local_file = os.path.join(root, file)
            relative_path = os.path.relpath(local_file, local_path)
            remote_file = os.path.join(remote_path, relative_path).replace("\\", "/")

            with open(local_file, "rb") as f:
                try:
                    supabase.storage.from_(bucket_name).upload(remote_file, f, {"upsert": "true"})
                    print(f"✅ Uploaded: {local_file} → {bucket_name}/{remote_file}")
                    uploaded_files.append(remote_file)
                except Exception as e:
                    print(f"❌ Failed: {local_file} → {bucket_name}/{remote_file} | {e}")
    return uploaded_files

def list_bucket_recursive(bucket_name, path="", indent=0):
    """
    Recursively lists all files/folders in a Supabase Storage bucket (tree view).
    """
    try:
        items = supabase.storage.from_(bucket_name).list(path)
        prefix = "   " * indent
        for item in items:
            if item.get("id") is None:  # Folder
                print(f"{prefix}📁 {item['name']}/")
                list_bucket_recursive(bucket_name, os.path.join(path, item['name']).replace("\\", "/"), indent + 1)
            else:  # File
                print(f"{prefix}📄 {item['name']}")
    except Exception as e:
        print(f"❌ Could not list {bucket_name}/{path}: {e}")

def cleanup_bucket(bucket_name, local_files, path=""):
    """
    Deletes remote files that no longer exist locally.
    """
    try:
        items = supabase.storage.from_(bucket_name).list(path)
        for item in items:
            remote_path = os.path.join(path, item["name"]).replace("\\", "/")
            if item.get("id") is None:  # Folder
                cleanup_bucket(bucket_name, local_files, remote_path)
            else:  # File
                if remote_path not in local_files:
                    supabase.storage.from_(bucket_name).remove(remote_path)
                    print(f"🗑️ Deleted remote file: {bucket_name}/{remote_path}")
    except Exception as e:
        print(f"❌ Cleanup failed for {bucket_name}/{path}: {e}")

if __name__ == "__main__":
    # Map local folders to Supabase buckets
    folders_to_sync = {
        "data": os.path.join(LOCAL_ROOT, "data"),
        "media": os.path.join(LOCAL_ROOT, "media"),
        "uploads_cv": os.path.join(LOCAL_ROOT, "uploads_cv"),
        "uploads_projects": os.path.join(LOCAL_ROOT, "uploads_projects"),
        "uploads_photo": os.path.join(LOCAL_ROOT, "uploads_photo"),
        "uploads_pending": os.path.join(LOCAL_ROOT, "uploads_pending"),
    }

    for bucket, path in folders_to_sync.items():
        if os.path.exists(path):
            print(f"\n🚀 Syncing folder: {path} → Supabase bucket: {bucket}")
            local_files = upload_folder(bucket, path)

            print(f"\n🧹 Cleaning up bucket: {bucket}")
            cleanup_bucket(bucket, local_files)

            print(f"\n📂 Tree view of bucket: {bucket}")
            list_bucket_recursive(bucket)
        else:
            print(f"⚠️ Skipped: {path} (folder not found)")
