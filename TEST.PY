# app.py
from flask import Flask, render_template_string, request, redirect, url_for, send_from_directory, flash, abort, session, jsonify
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
import csv
import secrets
import shutil
import math
import urllib.parse
import re
import json
from collections import Counter, defaultdict

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# ====== CONFIG ======
ADMIN_KEY = "calebadmin"  # change this for production
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

# Existing file areas
UPLOAD_DIR_APPROVED = os.path.join(BASE_DIR, "uploads_projects")
UPLOAD_DIR_PENDING = os.path.join(BASE_DIR, "uploads_pending")
UPLOAD_DIR_CV = os.path.join(BASE_DIR, "uploads_cv")

# Media areas
MEDIA_DIR = os.path.join(BASE_DIR, "media")
MEDIA_PROFILE = os.path.join(MEDIA_DIR, "profile")
MEDIA_HERO = os.path.join(MEDIA_DIR, "hero")
MEDIA_GALLERY = os.path.join(MEDIA_DIR, "gallery")

# Blog storage
BLOG_DIR = os.path.join(DATA_DIR, "blog")
BLOG_CSV = os.path.join(BLOG_DIR, "blogs.csv")

# Newsletter subscribers CSV (Phase 1 addition)
NEWSLETTER_CSV = os.path.join(DATA_DIR, "newsletter.csv")
NEWSLETTER_FIELDS = ["timestamp", "email"]

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR_APPROVED, exist_ok=True)
os.makedirs(UPLOAD_DIR_PENDING, exist_ok=True)
os.makedirs(UPLOAD_DIR_CV, exist_ok=True)
os.makedirs(MEDIA_DIR, exist_ok=True)
os.makedirs(MEDIA_PROFILE, exist_ok=True)
os.makedirs(MEDIA_HERO, exist_ok=True)
os.makedirs(MEDIA_GALLERY, exist_ok=True)
os.makedirs(BLOG_DIR, exist_ok=True)

# allowed extensions (includes common video types for gallery)
ALLOWED_EXTS = {"pdf", "doc", "docx", "png", "jpg", "jpeg", "zip", "txt", "ppt", "pptx", "webp", "gif", "mp4", "webm", "ogg", "mov", "m4v"}
IMAGE_EXTS = {"png", "jpg", "jpeg", "webp", "gif"}
VIDEO_EXTS = {"mp4", "webm", "ogg", "mov", "m4v"}
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB

MESSAGES_CSV = os.path.join(DATA_DIR, "messages.csv")
MSG_FIELDNAMES = ["timestamp", "name", "email", "message", "status"]
BLOG_FIELDNAMES = ["id", "timestamp", "title", "slug", "content"]

# ====== HELPERS ======
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTS

def allowed_image(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in IMAGE_EXTS

def allowed_video(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in VIDEO_EXTS

def save_message(name: str, email: str, message: str) -> None:
    newfile = not os.path.exists(MESSAGES_CSV)
    with open(MESSAGES_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if newfile:
            w.writerow(MSG_FIELDNAMES)
        w.writerow([datetime.now().isoformat(timespec="seconds"), name.strip(), email.strip(), message.strip(), "unread"])

def load_messages():
    msgs = []
    if os.path.exists(MESSAGES_CSV):
        with open(MESSAGES_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entry = {k: (row.get(k, "") if k in row else "") for k in MSG_FIELDNAMES}
                if not entry.get("status"):
                    entry["status"] = "unread"
                msgs.append(entry)
    return msgs

def save_all_messages(msgs):
    if not msgs:
        try:
            if os.path.exists(MESSAGES_CSV):
                os.remove(MESSAGES_CSV)
        except OSError:
            pass
        return
    with open(MESSAGES_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=MSG_FIELDNAMES)
        writer.writeheader()
        for r in msgs:
            out = {k: r.get(k, "") for k in MSG_FIELDNAMES}
            writer.writerow(out)

def list_projects():
    try:
        return sorted(os.listdir(UPLOAD_DIR_APPROVED))
    except FileNotFoundError:
        return []

def list_pending():
    try:
        return sorted(os.listdir(UPLOAD_DIR_PENDING))
    except FileNotFoundError:
        return []

def owner_cv_filename():
    files = sorted(os.listdir(UPLOAD_DIR_CV))
    return files[0] if files else None

def handle_upload(up, folder, rename_to=None):
    if not up or up.filename == "":
        return None, "No file selected."
    if not allowed_file(up.filename):
        return None, "Invalid file type."
    fname = rename_to or (datetime.now().strftime("%Y%m%d_%H%M%S_") + secure_filename(up.filename))
    up.save(os.path.join(folder, fname))
    return fname, None

def handle_image_upload(up, folder, rename_to=None):
    if not up or up.filename == "":
        return None, "No image selected."
    if not allowed_image(up.filename):
        return None, "Invalid image type."
    fname = rename_to or (datetime.now().strftime("%Y%m%d_%H%M%S_") + secure_filename(up.filename))
    up.save(os.path.join(folder, fname))
    return fname, None

def require_admin():
    if not session.get("is_admin"):
        flash("Please log in as admin.")
        return False
    return True

def latest_file(folder, only_images=False):
    try:
        entries = []
        for f in os.listdir(folder):
            if only_images and not allowed_image(f):
                continue
            p = os.path.join(folder, f)
            if os.path.isfile(p):
                entries.append((f, os.path.getmtime(p)))
        if not entries:
            return None, None
        entries.sort(key=lambda x: x[1], reverse=True)
        return entries[0]
    except FileNotFoundError:
        return None, None

def list_images(folder):
    """Return only image filenames in folder, newest-first (keeps backward compatibility)."""
    try:
        imgs = [f for f in os.listdir(folder) if allowed_image(f)]
        imgs.sort(key=lambda n: os.path.getmtime(os.path.join(folder, n)), reverse=True)
        return imgs
    except FileNotFoundError:
        return []

def list_gallery_media(folder=MEDIA_GALLERY):
    """
    Return list of gallery media items (images + videos), each item is a dict:
      { "name": "<filename>", "type": "image" or "video", "url": "<url>" }
    Sorted newest-first.
    """
    try:
        entries = []
        for f in os.listdir(folder):
            p = os.path.join(folder, f)
            if not os.path.isfile(p):
                continue
            ext = f.rsplit(".", 1)[-1].lower() if "." in f else ""
            if ext in IMAGE_EXTS or ext in VIDEO_EXTS:
                entries.append((f, os.path.getmtime(p)))
        if not entries:
            return []
        entries.sort(key=lambda x: x[1], reverse=True)
        out = []
        for fname, _ in entries:
            typ = "image" if allowed_image(fname) else "video" if allowed_video(fname) else "other"
            out.append({"name": fname, "type": typ, "url": media_url("gallery", fname)})
        return out
    except FileNotFoundError:
        return []

def media_url(kind, filename):
    if not filename:
        return None
    folder = MEDIA_PROFILE if kind == "profile" else MEDIA_HERO if kind == "hero" else MEDIA_GALLERY
    path = os.path.join(folder, filename)
    v = int(os.path.getmtime(path)) if os.path.exists(path) else 0
    return url_for("media_file", kind=kind, filename=filename) + f"?v={v}"

def slugify(text: str) -> str:
    s = text.lower().strip()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[-\s]+", "-", s)
    return s[:200]

# ====== BLOG HELPERS ======
def load_blogs():
    blogs = []
    if os.path.exists(BLOG_CSV):
        with open(BLOG_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                blogs.append(row)
    return blogs

def save_all_blogs(blogs):
    if not blogs:
        try:
            if os.path.exists(BLOG_CSV):
                os.remove(BLOG_CSV)
        except OSError:
            pass
        return
    with open(BLOG_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=BLOG_FIELDNAMES)
        writer.writeheader()
        for b in blogs:
            writer.writerow({k: b.get(k, "") for k in BLOG_FIELDNAMES})

def add_blog(title, content):
    blogs = load_blogs()
    nid = 1
    if blogs:
        try:
            nid = max(int(b.get("id", 0)) for b in blogs) + 1
        except Exception:
            nid = len(blogs) + 1
    slug = slugify(title) or f"post-{nid}"
    b = {
        "id": str(nid),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "title": title.strip(),
        "slug": slug,
        "content": content.strip()
    }
    blogs.insert(0, b)  # newest first
    save_all_blogs(blogs)
    return b

def delete_blog_by_id(bid):
    blogs = load_blogs()
    remaining = [b for b in blogs if b.get("id") != str(bid)]
    save_all_blogs(remaining)

# ====== NEWSLETTER HELPERS (Phase 1) ======
def save_subscriber(email: str) -> None:
    newfile = not os.path.exists(NEWSLETTER_CSV)
    with open(NEWSLETTER_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if newfile:
            w.writerow(NEWSLETTER_FIELDS)
        w.writerow([datetime.now().isoformat(timespec="seconds"), email.strip().lower()])

def load_subscribers():
    subs = []
    if os.path.exists(NEWSLETTER_CSV):
        with open(NEWSLETTER_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                subs.append(row)
    return subs

# ====== TEMPLATES (main page + blog and sections) ======
# Main PAGE with SEO meta + Open Graph and newsletter section and accessibility touches
PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Muga • Portfolio — Caleb Muga</title>

  <!-- SEO / OpenGraph -->
  <meta name="description" content="TechKnow Solutions — Caleb Muga: ICT Support, Networking, Cybersecurity, and process automation. Contact for services and view portfolio.">
  <meta name="author" content="Caleb Muga">
  <meta property="og:title" content="TechKnow Solutions — Caleb Muga">
  <meta property="og:description" content="ICT Support, Networking, Cybersecurity and automation solutions.">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="TechKnow Solutions">
  {% if hero_url %}
  <meta property="og:image" content="{{ hero_url }}">
  {% endif %}
  <meta name="twitter:card" content="summary_large_image">

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
  <style>
    :root{ --brand1:#0d6efd; --brand2:#6f42c1; --muted:#6b7280; }
    * { box-sizing: border-box; }
    body{
      font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background:#0b1220; color:#e6eef8; min-height:100vh; display:flex; flex-direction:column; overflow-x:hidden;
      transition: background .25s, color .25s;
    }
    /* LIGHT MODE */
    body.light { background: #f5f7fb; color: #0b1220; }
    .navbar{ font-size:1.05rem; backdrop-filter: saturate(160%) blur(6px); }
    .brand-avatar{ display:flex; align-items:center; gap:10px; text-decoration:none; font-weight:800; letter-spacing:.2px; }
    .brand-avatar img{ width:38px; height:38px; border-radius:50%; object-fit:cover; box-shadow:0 0 0 3px rgba(255,255,255,.15); }
    .brand-avatar span { color:#e5e7eb; }
    body.light .brand-avatar span { color: #0b1220; }
    .hero{ position:relative; color:#fff; padding:140px 24px 120px; text-align:center; border-bottom-left-radius:24px; border-bottom-right-radius:24px; overflow:hidden; }
    body.light .hero{ color:#0b1220; }
    .hero .overlay { position:absolute; inset:0; z-index:0; opacity:.28; background-size:cover; background-position:center; filter:saturate(120%) contrast(105%); }
    .hero h1{ position:relative; z-index:1; font-weight:800; font-size:3.2rem; letter-spacing:.3px; }
    .hero p{ position:relative; z-index:1; font-size:1.25rem; opacity:.95; }
    .chip{ display:inline-block; background:rgba(255,255,255,.12); padding:.35rem .7rem; border-radius:999px; font-size:.95rem; margin:0 .25rem .5rem; border:1px solid rgba(255,255,255,.2) }
    body.light .chip { background: rgba(10,10,10,.04); color:#0b1220; border:1px solid rgba(0,0,0,.06); }
    .floaters span{ position:absolute; width:120px; height:120px; border-radius:50%; background: radial-gradient(circle at 30% 30%, rgba(255,255,255,.12), rgba(255,255,255,.02)); animation: drift 16s ease-in-out infinite; filter: blur(1px); }
    .floaters span:nth-child(1){ left:5%; top:40%; animation-delay:0s; }
    .floaters span:nth-child(2){ right:8%; top:20%; animation-delay:2s; width:160px; height:160px; }
    .floaters span:nth-child(3){ left:20%; bottom:10%; animation-delay:4s; width:90px; height:90px; }
    .floaters span:nth-child(4){ right:20%; bottom:15%; animation-delay:6s; width:110px; height:110px; }
    @keyframes drift{ 0%,100%{ transform: translateY(0) translateX(0); } 50%{ transform: translateY(-18px) translateX(8px); } }
    section{ padding:80px 0; }
    h2.section-title{ font-weight:800; font-size:2rem; text-align:center; margin-bottom:24px; }
    .lead-lg{ font-size:1.15rem; color:#d0d8e6; }
    body.light .lead-lg { color: #374151; }
    .card{ border:0; border-radius:18px; background:#0f1724; box-shadow:0 8px 24px rgba(0,0,0,.55); color:#e6eef8; }
    body.light .card { background: #fff; color: #0b1220; box-shadow: 0 6px 18px rgba(0,0,0,.06); }
    .form-control, .form-select{ background:#0c1426; border:1px solid #1d2b4a; color:#dbe6ff; border-radius:12px; }
    body.light .form-control, body.light .form-select { background: #fff; color:#0b1220; border:1px solid #e6eef8; }
    .btn-primary{ background:linear-gradient(135deg, var(--brand1), var(--brand2)); border:0; }
    .gallery-grid{ display:grid; grid-template-columns: repeat(auto-fill, minmax(220px,1fr)); gap:14px; }
    .gallery-item{ position:relative; border-radius:14px; overflow:hidden; background:#0c1426; cursor:pointer; display:flex; align-items:center; justify-content:center; height:180px; }
    .gallery-item img, .gallery-item video{ width:100%; height:100%; object-fit:cover; transition: transform .4s ease; display:block; }
    .gallery-item:hover img, .gallery-item:hover video{ transform: scale(1.05); }
    .video-overlay { position:absolute; z-index:5; display:flex; align-items:center; justify-content:center; pointer-events:none; }
    .video-play-icon { width:56px; height:56px; background: rgba(0,0,0,0.45); border-radius:50%; display:flex; align-items:center; justify-content:center; }
    .video-play-icon:after{ content:""; border-style:solid; border-width:10px 0 10px 16px; border-color: transparent transparent transparent #fff; margin-left:4px; display:inline-block; }
    .reveal{ opacity:0; transform: translateY(18px); transition: all .7s ease; }
    .reveal.visible{ opacity:1; transform: translateY(0); }
    #loader{ position:fixed; inset:0; display:flex; align-items:center; justify-content:center; background:#0b1220; z-index:9999; }
    .spinner{ width:56px; height:56px; border-radius:50%; border:6px solid rgba(255,255,255,.15); border-top-color:#8aa4ff; animation:spin 1s linear infinite; }
    @keyframes spin{ to{ transform: rotate(360deg); } }
    .blog-card { padding:18px; border-radius:12px; background: rgba(255,255,255,0.02); }
    body.light .blog-card { background: #fff; border:1px solid #eef2ff; }
    .top-right-controls { display:flex; gap:8px; align-items:center; }
    .dark-toggle { cursor:pointer; border-radius:999px; padding:.35rem .6rem; background: rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.06); color:inherit; }
    body.light .dark-toggle { background: rgba(0,0,0,.03); }
    /* small responsive tweak for video thumbnails */
    @media (max-width:576px){ .gallery-item { height:140px; } }
  </style>
</head>
<body>

<div id="loader" role="status" aria-hidden="false"><div class="spinner" aria-hidden="true"></div></div>

<nav class="navbar navbar-expand-lg bg-transparent sticky-top" role="navigation" aria-label="Main navigation">
  <div class="container">
    <a class="brand-avatar" href="#home" aria-label="Go to home">
      {% if profile_url %}
        <img src="{{ profile_url }}" alt="profile">
        <span>Muga.dev</span>
      {% else %}
        <span class="fs-5">Muga<span style="color:#8aa4ff">.dev</span></span>
      {% endif %}
    </a>

    <div class="top-right-controls ms-auto d-flex align-items-center">
      <button id="themeBtn" class="dark-toggle" title="Toggle light / dark" aria-pressed="false">Toggle theme</button>
      <a class="btn btn-sm btn-outline-primary ms-2" href="{{ url_for('blog_list') }}">Blog</a>
      <a class="btn btn-sm btn-outline-secondary ms-2" href="{{ url_for('login') }}">Admin</a>
    </div>
  </div>
</nav>

<header id="home" class="hero" role="banner">
  {% if hero_url %}
    <div class="overlay" style="background-image: url('{{ hero_url }}');" aria-hidden="true"></div>
  {% endif %}
  <div class="floaters" aria-hidden="true">
    <span></span><span></span><span></span><span></span>
  </div>
  <div class="container position-relative">
    <h1 class="reveal">Hey, WELCOME TO TECHKNOW SOLUTIONS - Caleb Muga 👋</h1>
    <p class="mt-3 reveal" style="max-width:900px;margin:0 auto;">
      <span class="chip" aria-hidden="true">ICT Support</span>
      <span class="chip" aria-hidden="true">Networking</span>
      <span class="chip" aria-hidden="true">Cybersecurity</span>
      <span class="chip" aria-hidden="true">Process Automation</span>
    </p>
    <a href="#portfolio" class="btn btn-primary btn-lg mt-4 reveal">See My Work</a>
  </div>
</header>

<main class="container flex-grow-1" role="main">
  {% with msgs=get_flashed_messages() %}
    {% if msgs %}
      <div class="mt-4" aria-live="polite">
        {% for m in msgs %}
          <div class="alert alert-info">{{ m }}</div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  <!-- About -->
  <section id="about" class="reveal" aria-labelledby="about-title">
    <h2 class="section-title" id="about-title">About Me</h2>
    <div class="card p-4 mx-auto" style="max-width:1000px">
      <div class="row g-4">
        <div class="col-md-4 text-center">
          {% if profile_url %}
            <img src="{{ profile_url }}" style="width:160px;height:160px;object-fit:cover;border-radius:12px;" alt="Profile image of Caleb Muga">
          {% else %}
            <div style="width:160px;height:160px;border-radius:12px;display:flex;align-items:center;justify-content:center;background:#0c1426;font-weight:700;font-size:28px;" aria-hidden="true">
              CM
            </div>
          {% endif %}
        </div>
        <div class="col-md-8">
          <p class="lead-lg">
            Customer-focused ICT Officer with a BSc in Business & IT. Practical experience in network administration, end-user support,
            and cybersecurity. I build reliable tools and automate repetitive tasks to increase efficiency.
          </p>
          <ul>
            <li><strong>Strengths:</strong> Problem-solving, documentation, stakeholder communication, systems hardening.</li>
            <li><strong>Certifications:</strong> CCNA 1,OPSWAT File Security Associate, ALX Virtual Assistant.</li>
            <li><strong>Languages:</strong> English, Swahili.</li>
          </ul>
          {% if cv_file %}
            <a href="{{ url_for('download_file', kind='cv', filename=cv_file) }}" class="btn btn-outline-primary">Download CV</a>
          {% endif %}
        </div>
      </div>
    </div>
  </section>

  <!-- Portfolio / Gallery -->
  <section id="portfolio" class="reveal" aria-labelledby="portfolio-title">
    <h2 class="section-title" id="portfolio-title">Portfolio & Gallery</h2>
    <p class="text-center lead-lg">Featured gallery and private project submission.</p>

    <div class="card p-3 mb-4" aria-live="polite">
      <h5 class="mb-3">Featured Gallery ({{ gallery_images|length }})</h5>
      {% if gallery_images %}
        <div class="gallery-grid">
          {% for g in gallery_images %}
            <div class="gallery-item" onclick="openGalleryItem({{ loop.index0 }})" role="button" tabindex="0" aria-label="Open gallery item {{ loop.index }}">
              {% if g.type == 'image' %}
                <img src="{{ g.url }}" alt="Gallery image {{ loop.index }}">
              {% elif g.type == 'video' %}
                <video muted playsinline preload="metadata" aria-hidden="true">
                  <source src="{{ g.url }}">
                </video>
                <div class="video-overlay" aria-hidden="true"><div class="video-play-icon"></div></div>
              {% else %}
                <img src="{{ g.url }}" alt="Gallery {{ loop.index }}">
              {% endif %}
            </div>
          {% endfor %}
        </div>
      {% else %}
        <p class="text-muted mb-0">Gallery is empty. (Admin can add photos or videos in the Admin Panel.)</p>
      {% endif %}
    </div>

    <div class="card">
      <div class="card-body">
        <h5 class="card-title">Submit Your Project (Private)</h5>
        <p class="text-muted mb-2">Your file is uploaded privately and only the admin can view/approve it.</p>
        <form method="post" enctype="multipart/form-data" action="{{ url_for('upload_project') }}">
          <input type="file" name="file" class="form-control mb-2" required aria-label="Choose file to upload">
          <button class="btn btn-primary">Upload</button>
        </form>
        <small class="text-muted d-block mt-2">Allowed: {{ allowed_exts|join(', ') }} • up to 32MB</small>
      </div>
    </div>
  </section>

  <!-- Newsletter (Phase 1 addition) -->
  <section id="newsletter" class="reveal" aria-labelledby="newsletter-title">
    <h2 class="section-title" id="newsletter-title">Stay Updated</h2>
    <p class="text-center lead-lg">Subscribe to occasional updates and new blog posts.</p>
    <div class="card p-3 mx-auto" style="max-width:720px">
      <form method="post" action="{{ url_for('subscribe') }}" class="d-flex gap-2 align-items-center" aria-label="Subscribe to newsletter">
        <label for="sub-email" class="visually-hidden">Email address</label>
        <input id="sub-email" type="email" name="email" class="form-control" placeholder="Email address" required>
        <button class="btn btn-primary">Subscribe</button>
      </form>
      <div class="small text-muted mt-2">No spam. Unsubscribe anytime by contacting admin.</div>
    </div>
  </section>

  <!-- Services -->
  <section id="services" class="reveal">
    <h2 class="section-title">Services</h2>
    <div class="row g-4">
      <div class="col-md-4">
        <div class="card h-100 p-3">
          <h5>Network Administration</h5>
          <p class="mb-0">Design, deploy and maintain reliable networks (LAN/WAN, switches, routers, VPNs).</p>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card h-100 p-3">
          <h5>Cybersecurity</h5>
          <p class="mb-0">Vulnerability scanning, hardening, access control and incident response support.</p>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card h-100 p-3">
          <h5>Automation & Data Solutions</h5>
          <p class="mb-0">Dashboards, scripts and small automations that save time and reduce errors.</p>
        </div>
      </div>
    </div>
  </section>

  <!-- Blog preview -->
  <section id="blog" class="reveal">
    <h2 class="section-title">Latest from my blog</h2>
    <div class="row g-4">
      {% if blog_posts %}
        {% for b in blog_posts[:3] %}
          <div class="col-md-4">
            <div class="blog-card">
              <h5>{{ b.title }}</h5>
              <div class="text-muted" style="font-size:.9rem">{{ b.timestamp }}</div>
              <p style="margin-top:.6rem; color:inherit;">{{ b.content[:180] }}{% if b.content|length > 180 %}...{% endif %}</p>
              <a class="btn btn-sm btn-outline-primary" href="{{ url_for('view_blog', slug=b.slug) }}">Read</a>
            </div>
          </div>
        {% endfor %}
      {% else %}
        <div class="col-12"><p class="text-muted">No blog posts yet. (Admin can add posts.)</p></div>
      {% endif %}
    </div>
    <div class="text-center mt-3"><a class="btn btn-outline-secondary" href="{{ url_for('blog_list') }}">See all posts</a></div>
  </section>

  <!-- Contact -->
  <section id="contact" class="reveal">
    <h2 class="section-title">Contact</h2>
    <div class="row g-4">
      <div class="col-lg-6">
        <div class="card h-100">
          <div class="card-body">
            <h5 class="card-title">Send a Message</h5>
            <form method="post" action="{{ url_for('contact') }}">
              <input type="text" name="name" class="form-control mb-2" placeholder="Your name" required>
              <input type="email" name="email" class="form-control mb-2" placeholder="Your email" required>
              <textarea name="message" class="form-control mb-2" rows="4" placeholder="Your message" required></textarea>
              <button class="btn btn-primary">Send</button>
            </form>
            <small class="text-muted d-block mt-2">Your message is saved privately (admin can view).</small>
          </div>
        </div>
      </div>
      <div class="col-lg-6">
        <div class="card h-100">
          <div class="card-body">
            <h5 class="card-title">Quick Contacts</h5>
            <p class="lead mb-1"><strong>Phone:</strong> 0791 204 587</p>
            <a class="btn btn-whatsapp btn-lg" href="https://wa.me/254791204587" target="_blank" rel="noopener">Chat on WhatsApp</a>
            <p class="text-muted mt-3 mb-0">Available Mon–Sat. Nairobi time (EAT).</p>
          </div>
        </div>
      </div>
    </div>
  </section>

</main>

<footer>
  <div class="container d-flex flex-wrap justify-content-between align-items-center py-3">
    <div>© {{ year }} <strong>Caleb Muga</strong>. All rights reserved.</div>
    <div><a class="text-decoration-none" href="#home">Back to top ↑</a></div>
  </div>
</footer>

<!-- Media modal (images & videos) -->
<div class="modal fade" id="mediaModal" tabindex="-1" aria-hidden="true" aria-labelledby="mediaModalLabel">
  <div class="modal-dialog modal-dialog-centered modal-xl">
    <div class="modal-content" style="background:transparent;border:0;">
      <div class="modal-body p-0">
        <div id="mediaContainer" style="width:100%;height:auto;border-radius:12px;overflow:hidden;display:flex;align-items:center;justify-content:center;background:transparent;">
          <!-- JS injects media -->
        </div>
      </div>
    </div>
  </div>
</div>

<script>
  // Loader
  window.addEventListener('load', () => {
    const l = document.getElementById('loader');
    if(l){ l.style.opacity = '0'; setTimeout(() => l.style.display='none', 300); }
  });

  // Reveal on scroll
  const io = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if(e.isIntersecting){ e.target.classList.add('visible'); }
    });
  }, { threshold:.12 });
  document.querySelectorAll('.reveal').forEach(el => io.observe(el));

  // Gallery items as array
  const galleryItems = {{ gallery_images|tojson }};

  function openGalleryItem(idx){
    if(!galleryItems || idx < 0 || idx >= galleryItems.length) return;
    const it = galleryItems[idx];
    const container = document.getElementById('mediaContainer');
    container.innerHTML = '';
    if(it.type === 'image'){
      const img = document.createElement('img');
      img.src = it.url;
      img.alt = 'Gallery image';
      img.style.width = '100%';
      img.style.height = 'auto';
      img.style.display = 'block';
      img.style.borderRadius = '12px';
      container.appendChild(img);
    } else if(it.type === 'video'){
      const vid = document.createElement('video');
      vid.src = it.url;
      vid.controls = true;
      vid.autoplay = false;
      vid.playsInline = true;
      vid.style.width = '100%';
      vid.style.height = 'auto';
      vid.style.display = 'block';
      vid.style.borderRadius = '12px';
      container.appendChild(vid);
    } else {
      const a = document.createElement('a');
      a.href = it.url;
      a.innerText = 'Open media';
      a.target = '_blank';
      container.appendChild(a);
    }
    const modalEl = document.getElementById('mediaModal');
    const modal = new bootstrap.Modal(modalEl);
    modal.show();
  }

  // Theme toggle (persist in localStorage)
  const themeKey = 'muga_theme';
  const themeBtn = document.getElementById('themeBtn');
  function applyTheme(t){
    if(t==='light') {
      document.body.classList.add('light');
      themeBtn.setAttribute('aria-pressed', 'true');
    } else {
      document.body.classList.remove('light');
      themeBtn.setAttribute('aria-pressed', 'false');
    }
  }
  function initTheme(){
    const t = localStorage.getItem(themeKey) || 'dark';
    applyTheme(t);
  }
  initTheme();
  themeBtn.addEventListener('click', () => {
    const t = document.body.classList.contains('light') ? 'dark' : 'light';
    localStorage.setItem(themeKey, t);
    applyTheme(t);
  });

  // keyboard accessibility for gallery items (Enter to open)
  document.addEventListener('keydown', (e) => {
    if(e.key === 'Enter' && document.activeElement && document.activeElement.classList.contains('gallery-item')){
      const nodeList = Array.from(document.querySelectorAll('.gallery-item'));
      const idx = nodeList.indexOf(document.activeElement);
      if(idx >= 0) openGalleryItem(idx);
    }
  });
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# ====== ROUTES ======
@app.route("/", methods=["GET"])
def index():
    prof, _ = latest_file(MEDIA_PROFILE, only_images=True)
    hero, _ = latest_file(MEDIA_HERO, only_images=True)
    gallery = list_gallery_media(MEDIA_GALLERY)  # list of dicts {name,type,url}
    blogs = load_blogs()

    return render_template_string(
        PAGE,
        cv_file=owner_cv_filename(),
        allowed_exts=sorted(ALLOWED_EXTS),
        year=datetime.now().year,
        profile_url=media_url("profile", prof) if prof else None,
        hero_url=media_url("hero", hero) if hero else None,
        gallery_images=gallery,
        blog_posts=blogs
    )

# ====== Newsletter subscribe (Phase 1) ======
@app.route("/subscribe", methods=["POST"])
def subscribe():
    email = (request.form.get("email") or "").strip().lower()
    if not email or "@" not in email:
        flash("Please provide a valid email address.")
        return redirect(url_for("index") + "#newsletter")
    save_subscriber(email)
    flash("Thanks! You are subscribed to updates.")
    return redirect(url_for("index") + "#newsletter")

@app.route("/contact", methods=["POST"])
def contact():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    message = request.form.get("message", "").strip()
    if not (name and email and message):
        flash("Please fill in all fields.")
        return redirect(url_for("index") + "#contact")
    save_message(name, email, message)
    flash("Thanks, your message was received! ✅")
    return redirect(url_for("index") + "#contact")

@app.route("/upload_project", methods=["POST"])
def upload_project():
    up = request.files.get("file")
    fname, err = handle_upload(up, UPLOAD_DIR_PENDING)
    if err:
        flash(err)
    else:
        flash(f"Project '{fname}' uploaded (private). Admin will review. ✅")
    return redirect(url_for("index") + "#portfolio")

@app.route("/download/<kind>/<path:filename>")
def download_file(kind, filename):
    if kind == "project":
        return send_from_directory(UPLOAD_DIR_APPROVED, filename, as_attachment=True)
    elif kind == "cv":
        return send_from_directory(UPLOAD_DIR_CV, filename, as_attachment=True)
    abort(404)

@app.route("/media/<kind>/<path:filename>")
def media_file(kind, filename):
    safe = secure_filename(filename)
    if kind == "profile":
        return send_from_directory(MEDIA_PROFILE, safe)
    if kind == "hero":
        return send_from_directory(MEDIA_HERO, safe)
    if kind == "gallery":
        return send_from_directory(MEDIA_GALLERY, safe)
    abort(404)

# ====== BLOG PUBLIC ======
@app.route("/blog")
def blog_list():
    blogs = load_blogs()
    BLOG_PAGE = """
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Blog • Muga</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head><body style="background:#0b1220;color:#e6eef8">
      <div class="container py-5">
        <h1>Blog</h1>
        <p class="text-muted">Insights, tips and updates.</p>
        {% if blogs %}
          <div class="row g-4">
            {% for b in blogs %}
              <div class="col-md-4">
                <div style="background:#0f1724;padding:18px;border-radius:12px;">
                  <h5>{{ b.title }}</h5>
                  <div class="text-muted">{{ b.timestamp }}</div>
                  <p>{{ b.content[:160] }}{% if b.content|length>160 %}...{% endif %}</p>
                  <a class="btn btn-sm btn-outline-primary" href="{{ url_for('view_blog', slug=b.slug) }}">Read</a>
                </div>
              </div>
            {% endfor %}
          </div>
        {% else %}
          <p class="text-muted">No posts yet.</p>
        {% endif %}
        <a class="d-block mt-4 btn btn-outline-secondary" href="{{ url_for('index') }}">← Back</a>
      </div>
    </body></html>
    """
    return render_template_string(BLOG_PAGE, blogs=blogs)

@app.route("/blog/<slug>")
def view_blog(slug):
    blogs = load_blogs()
    post = next((b for b in blogs if b.get("slug") == slug), None)
    if not post:
        abort(404)
    BLOG_VIEW = """
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{{ post.title }} • Blog</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head><body style="background:#0b1220;color:#e6eef8">
      <div class="container py-5">
        <a href="{{ url_for('blog_list') }}" class="btn btn-sm btn-outline-secondary mb-3">← Back to Blog</a>
        <h1>{{ post.title }}</h1>
        <div class="text-muted mb-3">{{ post.timestamp }}</div>
        <div style="background:#0f1724;padding:18px;border-radius:12px;white-space:pre-wrap;">{{ post.content }}</div>
      </div>
    </body></html>
    """
    return render_template_string(BLOG_VIEW, post=post)

# ====== AUTH ======
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        code = request.form.get("code", "")
        if code == ADMIN_KEY:
            session["is_admin"] = True
            flash("Logged in as admin.")
            return redirect(url_for("admin"))
        flash("Wrong passcode.")
        return redirect(url_for("login"))
    LOGIN_PAGE = """
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Admin Login</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head><body style="background:#0b1220;color:#e6eef8">
      <div class="container py-5" style="max-width:480px;">
        <div style="background:#0f1724;padding:18px;border-radius:12px;">
          <h3>Admin Login</h3>
          {% with msgs=get_flashed_messages() %}{% if msgs %}{% for m in msgs %}<div class="alert alert-info">{{ m }}</div>{% endfor %}{% endif %}{% endwith %}
          <form method="post">
            <input class="form-control mb-2" type="password" name="code" placeholder="Enter admin passcode" required>
            <button class="btn btn-primary w-100">Login</button>
          </form>
          <a class="d-block mt-3" href="{{ url_for('index') }}">← Back to site</a>
        </div>
      </div>
    </body></html>
    """
    return render_template_string(LOGIN_PAGE)

@app.route("/logout")
def logout():
    session.pop("is_admin", None)
    flash("Logged out.")
    return redirect(url_for("index"))

# ====== ADMIN PANEL ======
@app.route("/admin")
def admin():
    if not require_admin():
        return redirect(url_for("login"))

    full_msgs = load_messages()
    total_messages = len(full_msgs)
    unread_count = sum(1 for m in full_msgs if m.get("status") == "unread")

    pending = list_pending()
    projects = list_projects()
    cv_file = owner_cv_filename()
    pending_count = len(pending)
    approved_count = len(projects)

    q = (request.args.get("q") or "").strip()
    show = request.args.get("show", "all")
    page = max(1, int(request.args.get("page", 1)))
    per_page = max(6, min(50, int(request.args.get("per_page", 12))))

    indexed = list(enumerate(full_msgs))
    if q:
        q_l = q.lower()
        filtered = [(i, m) for (i, m) in indexed if q_l in (m.get("name","").lower() + " " + m.get("email","").lower() + " " + m.get("message","").lower())]
    else:
        filtered = indexed

    if show == "unread":
        filtered = [(i, m) for (i, m) in filtered if m.get("status") == "unread"]

    total_filtered = len(filtered)
    pages = max(1, math.ceil(total_filtered / per_page))
    if page > pages: page = pages
    start = (page - 1) * per_page
    end = start + per_page
    page_items = filtered[start:end]
    display_msgs = []
    for (gid, m) in page_items:
        item = dict(m)
        item["gid"] = gid
        display_msgs.append(item)

    prof, _ = latest_file(MEDIA_PROFILE, only_images=True)
    hero, _ = latest_file(MEDIA_HERO, only_images=True)
    gal = list_gallery_media(MEDIA_GALLERY)  # gallery items (images + videos)
    blogs = load_blogs()
    subscribers = load_subscribers()

    # ADMIN_PAGE includes Chart.js analytics and improved message modal scripts
    ADMIN_PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin • Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body{background:#0b1220;color:#e6eef8;padding:18px}
      .card{border:0;border-radius:12px;background:#0f1724;padding:12px}
      .small-muted{ color:#9aa1b0 }
    </style>
    </head><body>
    <div class="container-fluid">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <div><h1 class="mb-0">Admin Panel</h1><div class="text-muted">Manage messages, uploads & media</div></div>
        <div class="d-flex gap-2">
          <a class="btn btn-outline-secondary" href="{{ url_for('export_messages') }}">Export CSV</a>
          <a class="btn btn-outline-secondary" href="{{ url_for('logout') }}">Logout</a>
        </div>
      </div>

      {% with msgs_flash = get_flashed_messages() %}
        {% if msgs_flash %}
          <div class="mb-3">
            {% for fm in msgs_flash %}<div class="alert alert-info">{{ fm }}</div>{% endfor %}
          </div>
        {% endif %}
      {% endwith %}

      <div class="row g-4">
        <div class="col-lg-7">
          <div class="card">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <h5>Messages ({{ total_filtered }})</h5>
              <form class="d-flex" method="get" style="gap:8px;">
                <input name="q" value="{{ q }}" class="form-control form-control-sm" placeholder="Search messages..." aria-label="Search messages">
                <select name="show" class="form-select form-select-sm" aria-label="Filter messages">
                  <option value="all" {% if show=='all' %}selected{% endif %}>All</option>
                  <option value="unread" {% if show=='unread' %}selected{% endif %}>Unread</option>
                </select>
                <input type="hidden" name="page" value="1">
                <button class="btn btn-primary btn-sm">Search</button>
              </form>
            </div>

            {% if display_msgs %}
              <div class="table-responsive">
                <table class="table table-sm table-striped" style="color:inherit;">
                  <thead><tr><th>#</th><th>When</th><th>Name</th><th>Email</th><th>Snippet</th><th>Actions</th></tr></thead>
                  <tbody>
                    {% for m in display_msgs %}
                      <tr>
                        <td>{{ loop.index + (page-1)*per_page }}</td>
                        <td>{{ m.timestamp }}</td>
                        <td>{{ m.name }} {% if m.status=='unread' %}<span style="color:#fff;background:#d63384;padding:2px 6px;border-radius:8px;font-size:.8rem;">unread</span>{% endif %}</td>
                        <td><a style="color:inherit" href="mailto:{{ m.email }}">{{ m.email }}</a></td>
                        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;">{{ m.message[:120] }}{% if m.message|length>120 %}...{% endif %}</td>
                        <td>
                          <button class="btn btn-sm btn-outline-primary" onclick="openMessageModal({{ m.gid }})">View</button>
                          <form method="post" action="{{ url_for('delete_message', mid=m.gid) }}" style="display:inline">
                            <button class="btn btn-sm btn-danger" onclick="return confirm('Delete?')">Delete</button>
                          </form>
                        </td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>

              <nav class="mt-2"><ul class="pagination pagination-sm">
                <li class="page-item {% if page<=1 %}disabled{% endif %}"><a class="page-link" href="{{ url_for('admin') }}?q={{ q|urlencode }}&show={{ show }}&page={{ page-1 }}&per_page={{ per_page }}">Previous</a></li>
                {% for p in range(1, pages+1) %}<li class="page-item {% if p==page %}active{% endif %}"><a class="page-link" href="{{ url_for('admin') }}?q={{ q|urlencode }}&show={{ show }}&page={{ p }}&per_page={{ per_page }}">{{ p }}</a></li>{% endfor %}
                <li class="page-item {% if page>=pages %}disabled{% endif %}"><a class="page-link" href="{{ url_for('admin') }}?q={{ q|urlencode }}&show={{ show }}&page={{ page+1 }}&per_page={{ per_page }}">Next</a></li>
              </ul></nav>
            {% else %}
              <p class="text-muted">No messages match your criteria.</p>
            {% endif %}
          </div>

          <!-- Analytics chart (Chart.js) -->
          <div class="card mt-3">
            <h5>Analytics (Messages last 30 days)</h5>
            <canvas id="messagesChart" width="400" height="120" aria-label="Messages chart"></canvas>
            <small class="text-muted d-block mt-2">This chart shows number of messages per day (last 30 days).</small>
          </div>

        </div>

        <div class="col-lg-5">
          <div class="card">
            <h5>Visitor Uploads (Pending) <small>({{ pending|length }})</small></h5>
            {% if pending %}
              <ul class="list-group mb-2">
                {% for f in pending %}
                  <li class="list-group-item d-flex justify-content-between align-items-center" style="background:#0f1724;color:inherit;border:1px solid #1d2b4a;">
                    <span style="max-width:60%;overflow:hidden;text-overflow:ellipsis;">{{ f }}</span>
                    <span class="d-flex gap-2">
                      <form method="post" action="{{ url_for('approve_file', filename=f) }}"><button class="btn btn-sm btn-success">Approve</button></form>
                      <form method="post" action="{{ url_for('reject_file', filename=f) }}"><button class="btn btn-sm btn-danger">Reject</button></form>
                    </span>
                  </li>
                {% endfor %}
              </ul>
            {% else %}
              <p class="text-muted">No pending uploads.</p>
            {% endif %}

            <hr>
            <h5>Approved Files</h5>
            {% if projects %}
              <ul class="list-group mb-2">
                {% for f in projects %}
                  <li class="list-group-item d-flex justify-content-between align-items-center" style="background:#0f1724;color:inherit;border:1px solid #1d2b4a;">
                    <span style="max-width:60%;overflow:hidden;text-overflow:ellipsis;">{{ f }}</span>
                    <span>
                      <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('download_file', kind='project', filename=f) }}">Download</a>
                      <form method="post" action="{{ url_for('delete_project', filename=f) }}" style="display:inline"><button class="btn btn-sm btn-danger">Delete</button></form>
                    </span>
                  </li>
                {% endfor %}
              </ul>
            {% else %}
              <p class="text-muted">No approved files yet.</p>
            {% endif %}

            <hr>
            <h5>Owner CV</h5>
            {% if cv_file %}
              <p>Latest CV: <strong>{{ cv_file }}</strong></p>
              <a class="btn btn-sm btn-outline-primary" href="{{ url_for('download_file', kind='cv', filename=cv_file) }}">Download CV</a>
            {% else %}
              <p class="text-muted">No CV uploaded yet.</p>
            {% endif %}
            <form method="post" enctype="multipart/form-data" action="{{ url_for('upload_cv_admin') }}" class="mt-2">
              <input type="file" name="cv" class="form-control form-control-sm mb-2" required>
              <button class="btn btn-warning btn-sm">Upload / Replace CV</button>
            </form>
          </div>

          <div class="card mt-3">
            <h5>Site Media</h5>
            <div class="mb-2">
              <div class="small-muted">Profile</div>
              {% if prof %}<img src="{{ url_for('media_file', kind='profile', filename=prof) }}" style="width:64px;height:64px;border-radius:8px;">{% else %}<div class="text-muted">None</div>{% endif %}
              <form method="post" enctype="multipart/form-data" action="{{ url_for('upload_profile_image') }}" class="mt-2">
                <input type="file" name="image" accept="image/*" class="form-control form-control-sm mb-2" required>
                <button class="btn btn-outline-primary btn-sm">Upload</button>
              </form>
            </div>
            <div class="mb-2">
              <div class="small-muted">Hero Background</div>
              {% if hero %}<img src="{{ url_for('media_file', kind='hero', filename=hero) }}" style="width:100%;height:80px;object-fit:cover;border-radius:8px;">{% else %}<div class="text-muted">None</div>{% endif %}
              <form method="post" enctype="multipart/form-data" action="{{ url_for('upload_hero_image') }}" class="mt-2">
                <input type="file" name="image" accept="image/*" class="form-control form-control-sm mb-2" required>
                <button class="btn btn-outline-primary btn-sm">Upload</button>
              </form>
            </div>

            <hr>
            <h6>Gallery</h6>
            <form method="post" enctype="multipart/form-data" action="{{ url_for('upload_gallery') }}">
              <input type="file" name="images" accept="image/*,video/*" multiple class="form-control form-control-sm mb-2" required>
              <button class="btn btn-primary btn-sm">Upload Image(s) / Video(s)</button>
            </form>
            {% if gal %}
              <ul class="list-group mt-2">
                {% for g in gal %}
                  <li class="list-group-item d-flex justify-content-between align-items-center" style="background:#0f1724;color:inherit;">
                    <div style="display:flex;align-items:center;gap:8px;">
                      {% if g.type == 'image' %}
                        <img src="{{ g.url }}" style="width:56px;height:56px;object-fit:cover;border-radius:8px;">
                      {% elif g.type == 'video' %}
                        <video muted playsinline preload="metadata" style="width:56px;height:56px;object-fit:cover;border-radius:8px;">
                          <source src="{{ g.url }}">
                        </video>
                      {% else %}
                        <img src="{{ g.url }}" style="width:56px;height:56px;object-fit:cover;border-radius:8px;">
                      {% endif %}
                      <span style="max-width:220px;overflow:hidden;text-overflow:ellipsis;">{{ g.name }}</span>
                    </div>
                    <form method="post" action="{{ url_for('delete_gallery_image', filename=g.name) }}"><button class="btn btn-sm btn-danger">Delete</button></form>
                  </li>
                {% endfor %}
              </ul>
            {% else %}
              <p class="text-muted mt-2">No gallery media yet.</p>
            {% endif %}
          </div>

        </div>
      </div>

      <hr>
      <h5>Blog Posts</h5>
      <div class="card">
        <form method="post" action="{{ url_for('admin_add_blog') }}">
          <input name="title" class="form-control mb-2" placeholder="Post title" required>
          <textarea name="content" class="form-control mb-2" rows="4" placeholder="Write post content (plain text)..." required></textarea>
          <button class="btn btn-primary btn-sm">Publish</button>
        </form>

        <hr>
        {% if blogs %}
          <ul class="list-group">
            {% for b in blogs %}
              <li class="list-group-item d-flex justify-content-between align-items-center" style="background:#0f1724;color:inherit;">
                <div>
                  <strong>{{ b.title }}</strong><div class="text-muted">{{ b.timestamp }}</div>
                </div>
                <div>
                  <a class="btn btn-sm btn-outline-primary" href="{{ url_for('view_blog', slug=b.slug) }}" target="_blank">View</a>
                  <form method="post" action="{{ url_for('admin_delete_blog', bid=b.id) }}" style="display:inline"><button class="btn btn-sm btn-danger">Delete</button></form>
                </div>
              </li>
            {% endfor %}
          </ul>
        {% else %}
          <p class="text-muted">No blog posts yet.</p>
        {% endif %}
      </div>

      <hr>
      <h5>Subscribers ({{ subscribers|length }})</h5>
      <div class="card">
        {% if subscribers %}
          <ul class="list-group">
            {% for s in subscribers %}
              <li class="list-group-item d-flex justify-content-between align-items-center" style="background:#0f1724;color:inherit;">
                <div>{{ s.get('email') }} <div class="text-muted small">{{ s.get('timestamp') }}</div></div>
              </li>
            {% endfor %}
          </ul>
        {% else %}
          <p class="text-muted">No subscribers yet.</p>
        {% endif %}
      </div>

    </div>

    <!-- Message modal -->
    <div class="modal fade" id="msgModal" tabindex="-1" aria-hidden="true">
      <div class="modal-dialog modal-lg modal-dialog-centered">
        <div class="modal-content" style="background:#0b1220;border:1px solid #1d2b4a;">
          <div class="modal-header"><h5 class="modal-title">Message details</h5><button class="btn-close" data-bs-dismiss="modal"></button></div>
          <div class="modal-body">
            <div><strong>From:</strong> <span id="modal-name"></span></div>
            <div class="mb-2"><strong>Email:</strong> <a id="modal-email" href=""></a></div>
            <div class="mb-2"><strong>When:</strong> <span id="modal-when"></span></div>
            <hr>
            <div id="modal-message" style="white-space:pre-wrap;"></div>
          </div>
          <div class="modal-footer">
            <button id="modal-toggle-read" class="btn btn-outline-primary">Mark read</button>
            <form id="modal-delete-form" method="post" action=""><button class="btn btn-danger" onclick="return confirm('Delete this message?')">Delete</button></form>
            <button class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
          </div>
        </div>
      </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
      // openMessageModal uses credentials and improved error handling
      function openMessageModal(gid){
        try {
          const base = '{{ url_for("message_json", mid=0) }}';
          const url = base.replace('/0', '/' + encodeURIComponent(gid));
          fetch(url, { credentials: 'same-origin' })
            .then(r => {
              if (!r.ok) {
                console.error('Failed to fetch message JSON, status:', r.status, r.statusText);
                throw new Error('Status ' + r.status);
              }
              return r.json();
            })
            .then(data => {
              document.getElementById('modal-name').innerText = data.name || '(no name)';
              const emailEl = document.getElementById('modal-email');
              emailEl.innerText = data.email || '(no email)'; emailEl.href = 'mailto:' + (data.email || '');
              document.getElementById('modal-when').innerText = data.timestamp || '';
              document.getElementById('modal-message').innerText = data.message || '';
              const form = document.getElementById('modal-delete-form'); form.action = '/admin/delete_message/' + encodeURIComponent(gid);
              const toggleBtn = document.getElementById('modal-toggle-read');
              // handler
              toggleBtn.onclick = function(){
                fetch('/admin/toggle_read_json/' + encodeURIComponent(gid), { method: 'POST', credentials: 'same-origin' })
                  .then(r => {
                    if (!r.ok) {
                      console.error('Toggle read failed, status:', r.status);
                      throw new Error('Toggle status ' + r.status);
                    }
                    return r.json();
                  })
                  .then(res => {
                    if (res.status) {
                      toggleBtn.innerText = res.status === 'read' ? 'Mark unread' : 'Mark read';
                    }
                  }).catch(e => {
                    alert('Could not toggle read/unread. See console for details.');
                    console.error(e);
                  });
              };
              toggleBtn.innerText = data.status === 'unread' ? 'Mark read' : 'Mark unread';
              const modal = new bootstrap.Modal(document.getElementById('msgModal')); modal.show();
            })
            .catch(e => {
              alert('Could not load message — check console for details.');
              console.error('openMessageModal error:', e);
            });
        } catch (err) {
          alert('An unexpected error occurred while opening the message.');
          console.error(err);
        }
      }

      // Chart: fetch analytics data endpoint and render
      async function loadMessagesChart() {
        try {
          const resp = await fetch('{{ url_for("admin_analytics_data") }}', { credentials: 'same-origin' });
          if(!resp.ok) throw new Error('Fetch analytics failed: ' + resp.status);
          const data = await resp.json();
          const ctx = document.getElementById('messagesChart').getContext('2d');
          const chart = new Chart(ctx, {
            type: 'bar',
            data: {
              labels: data.labels,
              datasets: [{
                label: 'Messages',
                data: data.values,
                borderRadius: 6,
                barPercentage: 0.8,
                categoryPercentage: 0.8
              }]
            },
            options: {
              responsive: true,
              plugins: {
                legend: { display: false },
                tooltip: { mode: 'index', intersect: false }
              },
              scales: {
                x: { ticks: { color: '#cbd5e1' } },
                y: { ticks: { color: '#cbd5e1' }, beginAtZero: true }
              }
            }
          });
        } catch (e) {
          console.error('loadMessagesChart error:', e);
        }
      }
      loadMessagesChart();
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </body></html>
    """
    return render_template_string(
        ADMIN_PAGE,
        total_messages=total_messages,
        unread_count=unread_count,
        pending_count=pending_count,
        approved_count=approved_count,
        display_msgs=display_msgs,
        pending=pending,
        projects=projects,
        cv_file=cv_file,
        q=q,
        show=show,
        page=page,
        pages=pages,
        per_page=per_page,
        total_filtered=total_filtered,
        prof=prof,
        hero=hero,
        gal=gal,
        blogs=blogs,
        subscribers=subscribers
    )

# ====== JSON endpoints (admin-only) ======
@app.route("/admin/message_json/<int:mid>", methods=["GET"])
def message_json(mid):
    if not require_admin():
        return jsonify({"error": "unauthorized"}), 403
    msgs = load_messages()
    if mid < 0 or mid >= len(msgs):
        return jsonify({"error": "not found"}), 404
    return jsonify(msgs[mid])

@app.route("/admin/toggle_read_json/<int:mid>", methods=["POST"])
def toggle_read_json(mid):
    if not require_admin():
        return jsonify({"error": "unauthorized"}), 403
    msgs = load_messages()
    if mid < 0 or mid >= len(msgs):
        return jsonify({"error": "not found"}), 404
    current = msgs[mid].get("status", "unread")
    new = "read" if current == "unread" else "unread"
    msgs[mid]["status"] = new
    save_all_messages(msgs)
    return jsonify({"status": new})

# ====== ADMIN Analytics data endpoint (Phase 1) ======
@app.route("/admin/analytics_data")
def admin_analytics_data():
    if not require_admin():
        return jsonify({"error": "unauthorized"}), 403
    # messages per day for last 30 days
    msgs = load_messages()
    now = datetime.now()
    days = 30
    counts = Counter()
    for m in msgs:
        ts = m.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts)
            # only last 30 days
            if dt >= now - timedelta(days=days-1):
                day = dt.date().isoformat()
                counts[day] += 1
        except Exception:
            continue
    labels = []
    values = []
    for d in (now.date() - timedelta(days=i) for i in reversed(range(days))):
        s = d.isoformat()
        labels.append(s)
        values.append(counts.get(s, 0))
    return jsonify({"labels": labels, "values": values})

# ====== MESSAGE DELETE ======
@app.route("/admin/delete_message/<int:mid>", methods=["POST"])
def delete_message(mid):
    if not require_admin():
        return redirect(url_for("login"))
    msgs = load_messages()
    if mid < 0 or mid >= len(msgs):
        flash("Message not found.")
        return redirect(url_for("admin"))
    deleted = msgs.pop(mid)
    save_all_messages(msgs)
    flash(f"Deleted message from {deleted.get('name','unknown')}.")
    return redirect(url_for("admin"))

# ====== Export messages CSV ======
@app.route("/admin/export_messages")
def export_messages():
    if not require_admin():
        return redirect(url_for("login"))
    if not os.path.exists(MESSAGES_CSV):
        flash("No messages to export.")
        return redirect(url_for("admin"))
    return send_from_directory(DATA_DIR, os.path.basename(MESSAGES_CSV), as_attachment=True)

# ====== PROJECT MANAGEMENT (admin) ======
@app.route("/admin/delete_project/<path:filename>", methods=["POST"])
def delete_project(filename):
    if not require_admin():
        return redirect(url_for("login"))
    fname = urllib.parse.unquote(filename)
    safe_name = secure_filename(fname)
    path = os.path.join(UPLOAD_DIR_APPROVED, safe_name)
    if os.path.exists(path):
        try:
            os.remove(path)
            flash(f"Deleted file '{safe_name}'.")
        except OSError:
            flash("Could not delete file.")
    else:
        flash("File not found.")
    return redirect(url_for("admin"))

@app.route("/admin/approve/<path:filename>", methods=["POST"])
def approve_file(filename):
    if not require_admin():
        return redirect(url_for("login"))
    fname = urllib.parse.unquote(filename)
    safe_name = secure_filename(fname)
    src = os.path.join(UPLOAD_DIR_PENDING, safe_name)
    dst = os.path.join(UPLOAD_DIR_APPROVED, safe_name)
    if os.path.exists(src):
        shutil.move(src, dst)
        flash(f"Approved '{safe_name}'.")
    else:
        flash("File not found.")
    return redirect(url_for("admin"))

@app.route("/admin/reject/<path:filename>", methods=["POST"])
def reject_file(filename):
    if not require_admin():
        return redirect(url_for("login"))
    fname = urllib.parse.unquote(filename)
    safe_name = secure_filename(fname)
    path = os.path.join(UPLOAD_DIR_PENDING, safe_name)
    if os.path.exists(path):
        os.remove(path)
        flash(f"Rejected '{safe_name}'.")
    else:
        flash("File not found.")
    return redirect(url_for("admin"))

# ====== CV UPLOAD (admin only) ======
@app.route("/admin/upload_cv", methods=["POST"])
def upload_cv_admin():
    if not require_admin():
        return redirect(url_for("login"))
    up = request.files.get("cv")
    if not up or up.filename == "":
        flash("No CV selected.")
        return redirect(url_for("admin"))
    if not allowed_file(up.filename):
        flash("Invalid file type.")
        return redirect(url_for("admin"))
    ext = up.filename.rsplit(".", 1)[1].lower()
    for f in os.listdir(UPLOAD_DIR_CV):
        try:
            os.remove(os.path.join(UPLOAD_DIR_CV, f))
        except OSError:
            pass
    fname = f"Caleb_Muga_CV.{ext}"
    up.save(os.path.join(UPLOAD_DIR_CV, secure_filename(fname)))
    flash("CV uploaded successfully! ✅")
    return redirect(url_for("admin"))

# ====== MEDIA UPLOADS (admin) ======
@app.route("/admin/upload_profile_image", methods=["POST"])
def upload_profile_image():
    if not require_admin():
        return redirect(url_for("login"))
    up = request.files.get("image")
    fname, err = handle_image_upload(up, MEDIA_PROFILE, rename_to=None)
    if err:
        flash(err)
        return redirect(url_for("admin"))
    for f in os.listdir(MEDIA_PROFILE):
        if f != fname:
            try:
                os.remove(os.path.join(MEDIA_PROFILE, f))
            except OSError:
                pass
    flash("Profile image updated. ✅")
    return redirect(url_for("admin"))

@app.route("/admin/upload_hero_image", methods=["POST"])
def upload_hero_image():
    if not require_admin():
        return redirect(url_for("login"))
    up = request.files.get("image")
    fname, err = handle_image_upload(up, MEDIA_HERO, rename_to=None)
    if err:
        flash(err)
        return redirect(url_for("admin"))
    for f in os.listdir(MEDIA_HERO):
        if f != fname:
            try:
                os.remove(os.path.join(MEDIA_HERO, f))
            except OSError:
                pass
    flash("Hero background updated. ✅")
    return redirect(url_for("admin"))

@app.route("/admin/upload_gallery", methods=["POST"])
def upload_gallery():
    if not require_admin():
        return redirect(url_for("login"))
    files = request.files.getlist("images")
    if not files:
        flash("Select at least one file.")
        return redirect(url_for("admin"))
    uploaded = 0
    for up in files:
        if not up or not up.filename:
            continue
        ext = up.filename.rsplit(".", 1)[-1].lower() if "." in up.filename else ""
        if ext in IMAGE_EXTS or ext in VIDEO_EXTS:
            fname = (datetime.now().strftime("%Y%m%d_%H%M%S_") + secure_filename(up.filename))
            up.save(os.path.join(MEDIA_GALLERY, fname))
            uploaded += 1
    if uploaded:
        flash(f"Uploaded {uploaded} item(s) to gallery. ✅")
    else:
        flash("No valid images or videos were uploaded.")
    return redirect(url_for("admin"))

@app.route("/admin/delete_gallery/<path:filename>", methods=["POST"])
def delete_gallery_image(filename):
    if not require_admin():
        return redirect(url_for("login"))
    fname = secure_filename(urllib.parse.unquote(filename))
    path = os.path.join(MEDIA_GALLERY, fname)
    if os.path.exists(path):
        try:
            os.remove(path)
            flash(f"Deleted gallery media '{fname}'.")
        except OSError:
            flash("Could not delete media.")
    else:
        flash("Media not found.")
    return redirect(url_for("admin"))

# ====== BLOG (admin create/delete) ======
@app.route("/admin/blogs/add", methods=["POST"])
def admin_add_blog():
    if not require_admin():
        return redirect(url_for("login"))
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    if not (title and content):
        flash("Title and content required.")
        return redirect(url_for("admin"))
    add_blog(title, content)
    flash("Blog post published.")
    return redirect(url_for("admin"))

@app.route("/admin/blogs/delete/<bid>", methods=["POST"])
def admin_delete_blog(bid):
    if not require_admin():
        return redirect(url_for("login"))
    delete_blog_by_id(bid)
    flash("Blog post deleted.")
    return redirect(url_for("admin"))

# ====== ERROR HANDLERS (Phase 1) ======
@app.errorhandler(404)
def page_not_found(e):
    PAGE_404 = """
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
      <title>404 Not Found</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head><body style="background:#0b1220;color:#e6eef8">
      <div class="container py-5 text-center">
        <h1>404 — Page not found</h1>
        <p>The page you're looking for doesn't exist.</p>
        <a class="btn btn-outline-secondary" href="{{ url_for('index') }}">Back to home</a>
      </div>
    </body></html>
    """
    return render_template_string(PAGE_404), 404

@app.errorhandler(500)
def server_error(e):
    PAGE_500 = """
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Server Error</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head><body style="background:#0b1220;color:#e6eef8">
      <div class="container py-5 text-center">
        <h1>500 — Server error</h1>
        <p>Something went wrong. Try again later.</p>
        <a class="btn btn-outline-secondary" href="{{ url_for('index') }}">Back to home</a>
      </div>
    </body></html>
    """
    return render_template_string(PAGE_500), 500

# ====== MAIN ======
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
