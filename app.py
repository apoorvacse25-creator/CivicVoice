from flask import (
    Flask, request, redirect, url_for, render_template_string,
    session, send_from_directory
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps
import sqlite3
import os
import re
import secrets
import io
import time
from datetime import datetime

# ---------------------------------------------------------
# APP SETUP
# ---------------------------------------------------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-for-real-use"
)

app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE = os.path.join(BASE_DIR, "suggestions.db")

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}

MAX_IMAGES = 3
MAX_IMAGE_SIZE = 5 * 1024 * 1024

# Demo admin credentials
# Change this before real deployment.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():

    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference_code TEXT UNIQUE NOT NULL,
            area TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Received',
            admin_note TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            suggestion_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT,
            FOREIGN KEY (suggestion_id)
            REFERENCES suggestions(id)
        )
    """)

    db.commit()
    db.close()


init_db()


# ---------------------------------------------------------
# CSRF PROTECTION
# ---------------------------------------------------------

def get_csrf_token():

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


@app.context_processor
def inject_helpers():

    return {
        "csrf_token": get_csrf_token
    }


def validate_csrf():

    token = request.form.get("csrf_token")

    return token and token == session.get("csrf_token")


# ---------------------------------------------------------
# CONTENT MODERATION
# ---------------------------------------------------------

PROFANITY_WORDS = {
    "fuck",
    "fucking",
    "shit",
    "bitch",
    "asshole",
    "bastard",
    "dick",
    "cunt",
    "whore",
    "slut"
}


THREAT_PHRASES = {
    "kill you",
    "kill him",
    "kill her",
    "bomb you",
    "burn your house",
    "attack you",
    "hurt you",
    "shoot you"
}


def moderate_text(text):

    cleaned = re.sub(r"[^a-zA-Z0-9\s]", " ", text.lower())

    words = set(cleaned.split())

    for word in PROFANITY_WORDS:

        if word in words:

            return False, "Your submission contains abusive or vulgar language."

    for phrase in THREAT_PHRASES:

        if phrase in cleaned:

            return False, "Threatening or harmful language is not allowed."

    return True, ""


# ---------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------

def allowed_file(filename):

    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in ALLOWED_EXTENSIONS


def generate_reference():

    db = get_db()

    while True:

        reference = "CIV-" + secrets.token_hex(4).upper()

        existing = db.execute(
            "SELECT id FROM suggestions WHERE reference_code = ?",
            (reference,)
        ).fetchone()

        if not existing:
            db.close()
            return reference


def process_image(file):

    if not file or not file.filename:
        return None

    if not allowed_file(file.filename):
        raise ValueError(
            "Only JPG, JPEG, PNG and WEBP images are allowed."
        )

    raw_data = file.read()

    if len(raw_data) > MAX_IMAGE_SIZE:
        raise ValueError(
            "Each image must be smaller than 5 MB."
        )

    try:

        image = Image.open(io.BytesIO(raw_data))

        image = ImageOps.exif_transpose(image)

        image.thumbnail((1600, 1600))

        if image.mode != "RGB":
            image = image.convert("RGB")

        filename = secrets.token_hex(16) + ".jpg"

        path = os.path.join(UPLOAD_FOLDER, filename)

        image.save(
            path,
            "JPEG",
            quality=85,
            optimize=True
        )

        return filename

    except Exception:

        raise ValueError(
            "One of the uploaded files is not a valid image."
        )


# ---------------------------------------------------------
# RATE LIMIT
# ---------------------------------------------------------

def too_many_submissions():

    now = time.time()

    history = session.get("submission_times", [])

    history = [
        timestamp
        for timestamp in history
        if now - timestamp < 3600
    ]

    if len(history) >= 5:

        session["submission_times"] = history

        return True

    return False


def record_submission():

    history = session.get("submission_times", [])

    history.append(time.time())

    session["submission_times"] = history[-5:]


# ---------------------------------------------------------
# MAIN PAGE
# ---------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def home():

    error = None

    if request.method == "POST":

        if not validate_csrf():

            error = "Invalid request. Please refresh the page and try again."

        elif too_many_submissions():

            error = (
                "You have reached the submission limit. "
                "Please try again later."
            )

        else:

            area = request.form.get("area", "").strip()
            category = request.form.get("category", "").strip()
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()

            if not area or not category or not title or not description:

                error = "Please fill in all required fields."

            elif len(area) > 80:

                error = "Area name is too long."

            elif len(title) > 100:

                error = "Title must be 100 characters or less."

            elif len(description) > 1500:

                error = "Description must be 1500 characters or less."

            else:

                combined_text = title + " " + description

                safe, moderation_message = moderate_text(combined_text)

                if not safe:

                    error = moderation_message

                else:

                    uploaded_files = request.files.getlist("photos")

                    valid_files = [
                        f for f in uploaded_files
                        if f and f.filename
                    ]

                    if len(valid_files) > MAX_IMAGES:

                        error = "You can upload a maximum of 3 photos."

                    else:

                        saved_images = []

                        try:

                            for image_file in valid_files:

                                saved = process_image(image_file)

                                if saved:
                                    saved_images.append(
                                        (saved, secure_filename(
                                            image_file.filename
                                        ))
                                    )

                            reference = generate_reference()

                            db = get_db()

                            cursor = db.execute("""
                                INSERT INTO suggestions
                                (
                                    reference_code,
                                    area,
                                    category,
                                    title,
                                    description,
                                    status,
                                    created_at
                                )
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            """, (
                                reference,
                                area,
                                category,
                                title,
                                description,
                                "Received",
                                datetime.now().strftime(
                                    "%Y-%m-%d %H:%M:%S"
                                )
                            ))

                            suggestion_id = cursor.lastrowid

                            for filename, original_name in saved_images:

                                db.execute("""
                                    INSERT INTO images
                                    (
                                        suggestion_id,
                                        filename,
                                        original_name
                                    )
                                    VALUES (?, ?, ?)
                                """, (
                                    suggestion_id,
                                    filename,
                                    original_name
                                ))

                            db.commit()
                            db.close()

                            record_submission()

                            return redirect(
                                url_for(
                                    "success",
                                    reference=reference
                                )
                            )

                        except Exception as e:

                            for filename, _ in saved_images:

                                path = os.path.join(
                                    UPLOAD_FOLDER,
                                    filename
                                )

                                if os.path.exists(path):
                                    os.remove(path)

                            error = (
                                "Something went wrong while saving "
                                "your submission. Please try again."
                            )

    return render_template_string(
        HOME_PAGE,
        error=error
    )


# ---------------------------------------------------------
# SUCCESS PAGE
# ---------------------------------------------------------

@app.route("/success/<reference>")
def success(reference):

    return render_template_string(
        SUCCESS_PAGE,
        reference=reference
    )


# ---------------------------------------------------------
# TRACK SUGGESTION
# ---------------------------------------------------------

@app.route("/track", methods=["GET", "POST"])
def track():

    suggestion = None
    error = None

    if request.method == "POST":

        reference = request.form.get(
            "reference",
            ""
        ).strip().upper()

        db = get_db()

        suggestion = db.execute("""
            SELECT
                reference_code,
                area,
                category,
                title,
                status,
                created_at
            FROM suggestions
            WHERE reference_code = ?
        """, (reference,)).fetchone()

        db.close()

        if not suggestion:

            error = "No suggestion was found with that reference number."

    return render_template_string(
        TRACK_PAGE,
        suggestion=suggestion,
        error=error
    )


# ---------------------------------------------------------
# SAFETY PAGE
# ---------------------------------------------------------

@app.route("/safety")
def safety():

    return render_template_string(SAFETY_PAGE)


# ---------------------------------------------------------
# ADMIN LOGIN
# ---------------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    error = None

    if request.method == "POST":

        if not validate_csrf():

            error = "Invalid request."

        else:

            username = request.form.get("username", "")
            password = request.form.get("password", "")

            if (
                username == ADMIN_USERNAME
                and check_password_hash(
                    ADMIN_PASSWORD_HASH,
                    password
                )
            ):

                session["admin_logged_in"] = True

                return redirect(
                    url_for("admin_dashboard")
                )

            error = "Incorrect username or password."

    return render_template_string(
        ADMIN_LOGIN_PAGE,
        error=error
    )


# ---------------------------------------------------------
# ADMIN DASHBOARD
# ---------------------------------------------------------

@app.route("/admin")
def admin_dashboard():

    if not session.get("admin_logged_in"):

        return redirect(
            url_for("admin_login")
        )

    db = get_db()

    suggestions = db.execute("""
        SELECT *
        FROM suggestions
        ORDER BY id DESC
    """).fetchall()

    db.close()

    return render_template_string(
        ADMIN_PAGE,
        suggestions=suggestions
    )


# ---------------------------------------------------------
# UPDATE STATUS
# ---------------------------------------------------------

@app.route("/admin/update/<int:suggestion_id>", methods=["POST"])
def update_status(suggestion_id):

    if not session.get("admin_logged_in"):

        return redirect(
            url_for("admin_login")
        )

    if not validate_csrf():

        return "Invalid request", 400

    status = request.form.get("status", "")

    allowed_statuses = {
        "Received",
        "Under Review",
        "Action Taken",
        "Closed"
    }

    if status not in allowed_statuses:

        return "Invalid status", 400

    admin_note = request.form.get(
        "admin_note",
        ""
    ).strip()

    db = get_db()

    db.execute("""
        UPDATE suggestions
        SET status = ?, admin_note = ?
        WHERE id = ?
    """, (
        status,
        admin_note,
        suggestion_id
    ))

    db.commit()
    db.close()

    return redirect(
        url_for("admin_dashboard")
    )


# ---------------------------------------------------------
# ADMIN VIEW PHOTO
# ---------------------------------------------------------

@app.route("/admin/image/<filename>")
def admin_image(filename):

    if not session.get("admin_logged_in"):

        return "Unauthorized", 401

    return send_from_directory(
        UPLOAD_FOLDER,
        filename
    )


# ---------------------------------------------------------
# ADMIN LOGOUT
# ---------------------------------------------------------

@app.route("/admin/logout")
def admin_logout():

    session.pop("admin_logged_in", None)

    return redirect(
        url_for("home")
    )


# ---------------------------------------------------------
# HTML / CSS
# ---------------------------------------------------------

STYLE = """
<style>

* {
    box-sizing: border-box;
}

:root {
    --navy: #173b57;
    --blue: #176b87;
    --light-blue: #eaf6fa;
    --green: #2f855a;
    --text: #1f2937;
    --muted: #64748b;
    --white: #ffffff;
    --background: #f5f8fb;
    --border: #dbe4ea;
}

body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: var(--background);
    color: var(--text);
    line-height: 1.6;
}

/* NAVBAR */

nav {
    background: var(--navy);
    color: white;
    padding: 16px 7%;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo {
    font-size: 23px;
    font-weight: bold;
}

.logo span {
    color: #8ed6e8;
}

nav a {
    color: white;
    text-decoration: none;
    margin-left: 25px;
    font-size: 15px;
}

nav a:hover {
    color: #9bdbea;
}

/* MAIN */

.container {
    max-width: 1100px;
    margin: auto;
    padding: 35px 20px;
}

/* HERO */

.hero {
    background: linear-gradient(135deg, #173b57, #176b87);
    color: white;
    border-radius: 24px;
    padding: 55px;
    margin-bottom: 30px;
    overflow: hidden;
}

.hero-content {
    max-width: 700px;
}

.hero h1 {
    font-size: 46px;
    line-height: 1.15;
    margin: 0 0 18px;
}

.hero h1 span {
    color: #a9e5ef;
}

.hero p {
    font-size: 18px;
    color: #e5f5f8;
    margin-bottom: 28px;
}

.hero-buttons {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
}

.primary-button {
    background: white;
    color: var(--navy);
    padding: 13px 22px;
    border-radius: 10px;
    text-decoration: none;
    font-weight: bold;
}

.secondary-button {
    border: 1px solid rgba(255,255,255,0.7);
    color: white;
    padding: 13px 22px;
    border-radius: 10px;
    text-decoration: none;
    font-weight: bold;
}

.primary-button:hover,
.secondary-button:hover {
    opacity: 0.9;
}

/* INFO CARDS */

.info-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 18px;
    margin-bottom: 30px;
}

.info-card {
    background: white;
    padding: 23px;
    border-radius: 16px;
    border: 1px solid var(--border);
}

.info-icon {
    font-size: 28px;
    margin-bottom: 8px;
}

.info-card h3 {
    margin: 5px 0;
}

.info-card p {
    color: var(--muted);
    font-size: 14px;
}

/* CARD */

.card {
    background: white;
    padding: 32px;
    border-radius: 20px;
    margin-bottom: 25px;
    border: 1px solid var(--border);
    box-shadow: 0 8px 25px rgba(23,59,87,0.05);
}

.card h2 {
    margin-top: 0;
    color: var(--navy);
}

/* FORM */

label {
    display: block;
    font-weight: bold;
    margin-top: 20px;
    margin-bottom: 7px;
}

input,
select,
textarea {
    width: 100%;
    padding: 13px;
    border: 1px solid #cbd5e1;
    border-radius: 9px;
    font-size: 15px;
    font-family: inherit;
    background: white;
}

input:focus,
select:focus,
textarea:focus {
    outline: 3px solid #ccecf2;
    border-color: var(--blue);
}

textarea {
    min-height: 140px;
    resize: vertical;
}

button {
    background: var(--blue);
    color: white;
    border: none;
    padding: 13px 23px;
    border-radius: 9px;
    font-size: 16px;
    cursor: pointer;
    margin-top: 20px;
    font-weight: bold;
}

button:hover {
    background: var(--navy);
}

/* PRIVACY BOX */

.privacy-box {
    background: var(--light-blue);
    border: 1px solid #c7e8ef;
    padding: 18px;
    border-radius: 12px;
    margin-top: 20px;
}

.privacy-box strong {
    color: var(--navy);
}

/* WARNING */

.warning {
    background: #fff7ed;
    border-left: 5px solid #f97316;
    padding: 16px;
    border-radius: 8px;
    margin-top: 20px;
}

/* ERROR */

.error {
    background: #fee2e2;
    color: #991b1b;
    padding: 15px;
    border-radius: 9px;
    margin-bottom: 20px;
}

/* SUCCESS */

.success {
    background: #ecfdf5;
    border: 1px solid #bbf7d0;
    color: #166534;
    padding: 35px;
    border-radius: 15px;
    text-align: center;
}

.reference {
    font-size: 30px;
    font-weight: bold;
    letter-spacing: 2px;
    margin: 20px;
    color: var(--navy);
}

/* TRACKING */

.status {
    display: inline-block;
    padding: 7px 13px;
    border-radius: 20px;
    background: #e0f2fe;
    color: #075985;
    font-weight: bold;
}

/* ADMIN */

.admin-item {
    background: white;
    border: 1px solid var(--border);
    padding: 25px;
    border-radius: 15px;
    margin-bottom: 20px;
}

img.preview {
    max-width: 180px;
    max-height: 140px;
    margin: 8px;
    border-radius: 8px;
}

.small {
    color: var(--muted);
    font-size: 14px;
}

footer {
    text-align: center;
    padding: 35px 20px;
    color: var(--muted);
    font-size: 14px;
}

/* MOBILE */

@media(max-width: 750px) {

    nav {
        flex-direction: column;
        gap: 12px;
    }

    nav a {
        margin: 5px;
    }

    .hero {
        padding: 32px 25px;
    }

    .hero h1 {
        font-size: 34px;
    }

    .info-grid {
        grid-template-columns: 1fr;
    }

    .card {
        padding: 23px;
    }

}

</style>
"""
HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>CivicVoice - Digital Suggestion Box</title>
""" + STYLE + """
</head>

<body>

<nav>

<div class="logo">
CivicVoice
</div>

<div>
<a href="/">Home</a>
<a href="/track">Track</a>
<a href="/safety">Safety</a>
</div>

</nav>

<div class="container">

<section class="hero">

<h1>Make Your Community Better</h1>

<p>
Share a local problem, suggestion or improvement idea
with your local governance team.
</p>

<p>
Your personal details are not required.
Only your area is collected so the issue can reach
the appropriate local team.
</p>

</section>


<div class="card">

<h2>Submit a Suggestion or Problem</h2>

{% if error %}
<div class="error">
{{ error }}
</div>
{% endif %}

<form method="POST"
      enctype="multipart/form-data">

<input
type="hidden"
name="csrf_token"
value="{{ csrf_token() }}"
>


<label>
Area / Locality *
</label>

<input
type="text"
name="area"
placeholder="Example: Jayanagar 4th Block"
maxlength="80"
required


<p class="small">
Enter only your locality or ward.
Do not enter your house number or full address.
</p>


<label>
Category *
</label>

<select name="category" required>

<option value="">Select a category</option>

<option>Roads & Streets</option>
<option>Waste & Cleanliness</option>
<option>Water Supply</option>
<option>Street Lighting</option>
<option>Public Safety</option>
<option>Parks & Public Spaces</option>
<option>Public Transport</option>
<option>Other</option>

</select>


<label>
Short Title *
</label>

<input
type="text"
name="title"
placeholder="Example: Street light not working"
maxlength="100"
required
>


<label>
Describe the Problem *
</label>

<textarea
name="description"
maxlength="1500"
placeholder="Explain what is happening and where it is happening..."
required
></textarea>


<label>
Upload Photos
</label>

<input
type="file"
name="photos"
accept="image/jpeg,image/png,image/webp"
multiple
>

<p class="small">
You can upload up to 3 photos. Maximum 5 MB each.
</p>


<div class="warning">

<strong>Safety & Privacy:</strong>

<br><br>

Please do not upload:

<ul>

<li>Personal documents</li>
<li>Phone numbers or email addresses</li>
<li>Photos containing private information</li>
<li>Threats or abusive content</li>
<li>Unnecessary photos of people</li>

</ul>

Photos are kept private and are only available to authorized
administrators for reviewing the reported issue.

</div>


<button type="submit">
Submit Safely
</button>

</form>

</div>


<div class="card">

<h2>Already Submitted?</h2>

<p>
Use your anonymous reference number to check the status
of your suggestion.
</p>

<a href="/track">
<button>Track My Suggestion</button>
</a>

</div>

</div>

<footer>

CivicVoice • Digital Suggestion Box

</footer>

</body>
</html>
"""


# ---------------------------------------------------------
# SUCCESS HTML
# ---------------------------------------------------------

SUCCESS_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Submission Received</title>
""" + STYLE + """
</head>

<body>

<nav>

<div class="logo">CivicVoice</div>

<a href="/">Home</a>

</nav>

<div class="container">

<div class="card success">

<h1>Thank You!</h1>

<p>
Your suggestion has been safely submitted.
</p>

<p>
Your anonymous reference number is:
</p>

<div class="reference">
{{ reference }}
</div>

<p>
Save this number. You can use it later to check
the status of your suggestion.
</p>

<a href="/track">
<button>Track Suggestion</button>
</a>

<br>

<a href="/">
<button>Submit Another</button>
</a>

</div>

</div>

</body>
</html>
"""


# ---------------------------------------------------------
# TRACK HTML
# ---------------------------------------------------------

TRACK_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Track Suggestion</title>
""" + STYLE + """
</head>

<body>

<nav>

<div class="logo">CivicVoice</div>

<div>
<a href="/">Home</a>
<a href="/safety">Safety</a>
</div>

</nav>

<div class="container">

<div class="card">

<h2>Track Your Suggestion</h2>

{% if error %}
<div class="error">
{{ error }}
</div>
{% endif %}

<form method="POST">

<input
type="hidden"
name="csrf_token"
value="{{ csrf_token() }}"
>

<label>
Reference Number
</label>

<input
type="text"
name="reference"
placeholder="Example: CIV-A1B2C3D4"
required
>

<button type="submit">
Check Status
</button>

</form>

</div>


{% if suggestion %}

<div class="card">

<h2>{{ suggestion["title"] }}</h2>

<p>
<strong>Area:</strong>
{{ suggestion["area"] }}
</p>

<p>
<strong>Category:</strong>
{{ suggestion["category"] }}
</p>

<p>
<strong>Status:</strong>

<span class="status">
{{ suggestion["status"] }}
</span>

</p>

<p class="small">
Submitted:
{{ suggestion["created_at"] }}
</p>

</div>

{% endif %}

</div>

</body>
</html>
"""


# ---------------------------------------------------------
# SAFETY HTML
# ---------------------------------------------------------

SAFETY_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Safety & Privacy</title>
""" + STYLE + """
</head>

<body>

<nav>

<div class="logo">CivicVoice</div>

<a href="/">Home</a>

</nav>

<div class="container">

<div class="card">

<h1>Safety & Privacy</h1>

<h2>Your Privacy</h2>

<p>
CivicVoice does not ask citizens for their name,
phone number, email address or full home address.
</p>

<p>
The administrator receives the area and the
suggestion details needed to investigate the issue.
</p>


<h2>Respectful Communication</h2>

<p>
Abusive, vulgar, threatening or harmful language
is automatically rejected.
</p>


<h2>Photos</h2>

<p>
Photos can be used as evidence for a local problem,
but they should not contain personal documents,
private information or unnecessary identifiable people.
</p>


<h2>Purpose</h2>

<p>
The purpose of this platform is constructive
community improvement and communication with
local governance.
</p>

</div>

</div>

</body>
</html>
"""


# ---------------------------------------------------------
# ADMIN LOGIN HTML
# ---------------------------------------------------------

ADMIN_LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Admin Login</title>
""" + STYLE + """
</head>

<body>

<div class="container">

<div class="card">

<h2>Administrator Login</h2>

{% if error %}

<div class="error">
{{ error }}
</div>

{% endif %}

<form method="POST">

<input
type="hidden"
name="csrf_token"
value="{{ csrf_token() }}"
>

<label>
Username
</label>

<input
type="text"
name="username"
required
>

<label>
Password
</label>

<input
type="password"
name="password"
required
>

<button type="submit">
Login
</button>

</form>

</div>

</div>

</body>
</html>
"""


# ---------------------------------------------------------
# ADMIN DASHBOARD HTML
# ---------------------------------------------------------

ADMIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Admin Dashboard</title>
""" + STYLE + """
</head>

<body>

<nav>

<div class="logo">
CivicVoice Admin
</div>

<a href="/admin/logout">
Logout
</a>

</nav>

<div class="container">

<h1>Suggestion Dashboard</h1>

<p class="small">
Citizen personal details are not collected or displayed.
</p>


{% if suggestions %}

{% for suggestion in suggestions %}

<div class="admin-item">

<h2>
{{ suggestion["title"] }}
</h2>

<p>
<strong>Reference:</strong>
{{ suggestion["reference_code"] }}
</p>

<p>
<strong>Area:</strong>
{{ suggestion["area"] }}
</p>

<p>
<strong>Category:</strong>
{{ suggestion["category"] }}
</p>

<p>
<strong>Description:</strong>
{{ suggestion["description"] }}
</p>

<p>
<strong>Submitted:</strong>
{{ suggestion["created_at"] }}
</p>


<form method="POST"
      action="/admin/update/{{ suggestion['id'] }}">

<input
type="hidden"
name="csrf_token"
value="{{ csrf_token() }}"
>


<label>
Update Status
</label>

<select name="status">

<option
{% if suggestion["status"] == "Received" %}selected{% endif %}
>
Received
</option>

<option
{% if suggestion["status"] == "Under Review" %}selected{% endif %}
>
Under Review
</option>

<option
{% if suggestion["status"] == "Action Taken" %}selected{% endif %}
>
Action Taken
</option>

<option
{% if suggestion["status"] == "Closed" %}selected{% endif %}
>
Closed
</option>

</select>


<label>
Internal Admin Note
</label>

<textarea
name="admin_note"
placeholder="Internal note..."
>{{ suggestion["admin_note"] }}</textarea>


<button type="submit">
Save Update
</button>

</form>

</div>

{% endfor %}

{% else %}

<div class="card">

<p>
No suggestions have been submitted yet.
</p>

</div>

{% endif %}

</div>

</body>
</html>
"""


# ---------------------------------------------------------
# RUN APP
# ---------------------------------------------------------

if __name__ == "__main__":

    print("")
    print("====================================")
    print(" CivicVoice Digital Suggestion Box")
    print("====================================")
    print("")
    print("Website: http://127.0.0.1:5000")
    print("Admin:   http://127.0.0.1:5000/admin")
    print("")
    print("Demo admin username:", ADMIN_USERNAME)
    print("Demo admin password:", ADMIN_PASSWORD)
    print("")

    app.run(debug=True)
