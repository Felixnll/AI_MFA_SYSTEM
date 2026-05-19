from flask import Flask, render_template, request, redirect, session, jsonify
import json
import os
from pathlib import Path
import random
import smtplib
import ssl
from email.mime.text import MIMEText
from datetime import datetime
import time

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-in-production"

# Lightweight .env loader: if a .env file exists in project root, load keys into os.environ
def load_dotenv_file(path='.env'):
    p = Path(path)
    if not p.exists():
        return
    try:
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, val = line.split('=', 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            # Do not overwrite existing environment vars
            if os.getenv(key) is None:
                os.environ[key] = val
    except Exception:
        pass

load_dotenv_file()

USERS_FILE = "users.json"
OTP_STORE_FILE = "otp_store.json"

login_tracker = {}

def load_users():
    """Load users from JSON database"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def load_otp_store():
    """Load temporary OTP storage from JSON file."""
    if os.path.exists(OTP_STORE_FILE):
        with open(OTP_STORE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_otp_store(otp_data):
    """Persist OTP storage to JSON file."""
    with open(OTP_STORE_FILE, "w") as f:
        json.dump(otp_data, f, indent=2)


def generate_otp():
    """Generate a 6-digit OTP code."""
    return str(random.randint(100000, 999999))


def get_login_state(username):
    """Return or initialize tracking state for a user."""
    if username not in login_tracker:
        login_tracker[username] = {
            "failed_attempts": 0,
            "last_attempt_time": None,
            "blocked_until": 0,
        }
    return login_tracker[username]


def extract_features(username, user_record, password_match, device_id):
    """Extract simple login risk features."""
    state = get_login_state(username)
    current_time = time.time()
    last_attempt_time = state["last_attempt_time"]
    short_interval = last_attempt_time is not None and (current_time - last_attempt_time) < 5
    unusual_hour = datetime.now().hour < 6
    unknown_device = device_id.strip() != user_record.get("known_device", "")

    return {
        "failed_attempts": state["failed_attempts"],
        "short_interval": short_interval,
        "unknown_device": unknown_device,
        "unusual_hour": unusual_hour,
        "password_match": password_match,
    }


def simple_risk_engine(features):
    """Convert login features into a low/medium/high risk level."""
    score = 0

    if features["failed_attempts"] >= 3:
        score += 2
    if features["short_interval"]:
        score += 2
    if features["unknown_device"]:
        score += 1
    if features["unusual_hour"]:
        score += 1
    if not features["password_match"]:
        score += 2

    if score >= 5:
        return "high", score
    if score >= 3:
        return "medium", score
    return "low", score


def send_otp_email(receiver_email, username, otp_code):
    """Send OTP email using SMTP configuration from environment variables.

    Returns:
        (bool, str): success flag and diagnostic message.
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender_email = os.getenv("SMTP_SENDER", smtp_user)

    if not receiver_email:
        return False, "User email is missing in users.json."

    if not all([smtp_host, smtp_port, smtp_user, smtp_password, sender_email]):
        return False, "SMTP environment variables are missing in this terminal session."

    subject = "Your Securoserv OTP Code"
    body = (
        f"Hello {username},\n\n"
        f"Your one-time password (OTP) is: {otp_code}\n"
        "This OTP is for your Securoserv login and should not be shared.\n\n"
        "If this was not you, please ignore this email."
    )

    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = receiver_email

    try:
        smtp_port_int = int(smtp_port)
        
        # Use SSL_TLS context
        context = ssl.create_default_context()
        
        if smtp_port_int == 465:
            # Port 465 uses SSL from the start
            server = smtplib.SMTP_SSL(smtp_host, smtp_port_int, context=context, timeout=15)
        else:
            # Port 587 uses STARTTLS
            server = smtplib.SMTP(smtp_host, smtp_port_int, timeout=15)
            server.starttls(context=context)
        
        server.login(smtp_user, smtp_password)
        server.sendmail(sender_email, [receiver_email], message.as_string())
        server.quit()
        return True, "OTP email sent successfully."
    except Exception as exc:
        print(f"[OTP EMAIL ERROR] {exc}")
        return False, f"SMTP send failed: {exc}"

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        device_id = request.form.get("device_id", "")
        
        users = load_users()

        if username in users:
            state = get_login_state(username)
            current_time = time.time()
            if current_time < state["blocked_until"]:
                remaining_seconds = int(state["blocked_until"] - current_time)
                return render_template(
                    "access_denied.html",
                    username=username,
                    denial_type="blocked",
                    remaining_seconds=remaining_seconds,
                    reason=f"Access temporarily blocked. Try again in {remaining_seconds} seconds.",
                )
        
        # Validate credentials against database
        if username in users and password == users[username]["password"]:
            state = get_login_state(username)
            state["last_attempt_time"] = time.time()
            features = extract_features(username, users[username], True, device_id)
            risk_level, risk_score = simple_risk_engine(features)

            session["risk_level"] = risk_level
            session["risk_score"] = risk_score

            if risk_level == "high":
                state["blocked_until"] = time.time() + 60
                return render_template(
                    "access_denied.html",
                    username=username,
                    denial_type="blocked",
                    remaining_seconds=60,
                    reason="High-risk login detected. Access temporarily blocked for 60 seconds.",
                )

            if risk_level == "medium":
                # For medium risk, require a short client-visible delay before OTP verification.
                # Store the delay end timestamp in session so the OTP page can show a countdown.
                session["delay_until"] = time.time() + 10

            state["failed_attempts"] = 0
            state["blocked_until"] = 0

            otp_code = generate_otp()
            otp_store = load_otp_store()
            otp_store[username] = otp_code
            save_otp_store(otp_store)

            session["pending_user"] = username
            session["otp_sent"] = False

            receiver_email = users[username].get("email", "")
            # For medium risk we defer delivery until the client-side delay expires.
            if risk_level == "medium":
                session["otp_delivery_message"] = "OTP will be sent after short delay."
            else:
                email_sent, email_message = send_otp_email(receiver_email, username, otp_code)
                if email_sent:
                    session["otp_delivery_message"] = f"OTP sent to {receiver_email}."
                    session["otp_sent"] = True
                else:
                    # Development fallback when SMTP is not configured.
                    print(f"[OTP FALLBACK] {username}: {otp_code}")
                    session["otp_delivery_message"] = f"{email_message} Using terminal OTP fallback for testing."
                    session["otp_sent"] = True

            return redirect("/otp")

        if username in users:
            state = get_login_state(username)
            state["failed_attempts"] += 1
            state["last_attempt_time"] = time.time()
            features = extract_features(username, users[username], False, device_id)
            risk_level, risk_score = simple_risk_engine(features)

            if risk_level == "high":
                state["blocked_until"] = time.time() + 60
                return render_template(
                    "access_denied.html",
                    username=username,
                    denial_type="blocked",
                    remaining_seconds=60,
                    reason="High-risk login detected. Access temporarily blocked for 60 seconds.",
                )

        return render_template(
            "login.html",
            error_message="Invalid username or password.",
        )

    return render_template("login.html", error_message=None)


@app.route("/otp", methods=["GET", "POST"])
def otp_verification():
    username = session.get("pending_user")

    if not username:
        return redirect("/")

    if request.method == "POST":
        submitted_otp = request.form.get("otp", "").strip()
        otp_store = load_otp_store()
        expected_otp = otp_store.get(username)

        if submitted_otp == expected_otp:
            otp_store.pop(username, None)
            save_otp_store(otp_store)
            # Clear pending session keys related to verification/delay
            session.pop("pending_user", None)
            session.pop("delay_until", None)
            session.pop("otp_warning_message", None)
            session.pop("otp_delivery_message", None)
            return render_template(
                "main.html",
                username=username,
                risk_level=session.get("risk_level", "unknown"),
            )

        return render_template(
            "access_denied.html",
            username=username,
            denial_type="invalid_otp",
            reason="Invalid OTP. Access denied.",
        )

    # Clear any leftover warning message (we use countdown + delivery message only)
    session.pop("otp_warning_message", None)

    # If a medium-risk delay expired and the OTP hasn't been sent yet, send it now
    delay_until = session.get("delay_until")
    otp_sent = session.get("otp_sent", False)
    if delay_until and time.time() >= delay_until and not otp_sent:
        users = load_users()
        receiver_email = users.get(username, {}).get("email", "")
        otp_store = load_otp_store()
        otp_code = otp_store.get(username)
        if otp_code:
            email_sent, email_message = send_otp_email(receiver_email, username, otp_code)
            if email_sent:
                session["otp_delivery_message"] = f"OTP sent to {receiver_email}."
            else:
                print(f"[OTP FALLBACK] {username}: {otp_code}")
                session["otp_delivery_message"] = f"{email_message} Using terminal OTP fallback for testing."
            session["otp_sent"] = True

    return render_template(
        "otp.html",
        username=username,
        risk_level=session.get("risk_level", "unknown"),
        warning_message=session.get("otp_warning_message", ""),
        delivery_message=session.get("otp_delivery_message", ""),
        delay_until=session.get("delay_until", 0),
        error_message=None,
    )


@app.route("/send_deferred_otp", methods=["POST"])
def send_deferred_otp():
    username = session.get("pending_user")
    if not username:
        return jsonify({"success": False, "message": "No pending user in session."}), 400

    delay_until = session.get("delay_until")
    otp_sent = session.get("otp_sent", False)

    if not delay_until or time.time() < delay_until:
        return jsonify({"success": False, "message": "Delay not yet expired."}), 400

    if otp_sent:
        return jsonify({"success": True, "message": session.get("otp_delivery_message", "Already sent.")})

    users = load_users()
    receiver_email = users.get(username, {}).get("email", "")
    otp_store = load_otp_store()
    otp_code = otp_store.get(username)

    if not otp_code:
        return jsonify({"success": False, "message": "OTP not found."}), 400

    email_sent, email_message = send_otp_email(receiver_email, username, otp_code)
    if email_sent:
        session["otp_delivery_message"] = f"OTP sent to {receiver_email}."
    else:
        print(f"[OTP FALLBACK] {username}: {otp_code}")
        session["otp_delivery_message"] = f"{email_message} Using terminal OTP fallback for testing."

    session["otp_sent"] = True
    return jsonify({"success": True, "message": session["otp_delivery_message"]})


@app.route('/debug_env', methods=['GET'])
def debug_env():
    # Return SMTP environment variables (mask password) to help debug environment visibility
    smtp_host = os.getenv('SMTP_HOST')
    smtp_port = os.getenv('SMTP_PORT')
    smtp_user = os.getenv('SMTP_USER')
    smtp_password = os.getenv('SMTP_PASSWORD')
    smtp_sender = os.getenv('SMTP_SENDER')
    return jsonify({
        'SMTP_HOST': smtp_host,
        'SMTP_PORT': smtp_port,
        'SMTP_USER': smtp_user,
        'SMTP_PASSWORD_masked': None if smtp_password is None else ('*' * 6 + smtp_password[-2:]),
        'SMTP_SENDER': smtp_sender,
    })

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
