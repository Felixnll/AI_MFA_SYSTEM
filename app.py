from flask import Flask, render_template, request, redirect, session
import json
import os
import random
import smtplib
import ssl
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-in-production"

USERS_FILE = "users.json"
OTP_STORE_FILE = "otp_store.json"

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
        
        users = load_users()
        
        # Validate credentials against database
        if username in users and password == users[username]["password"]:
            otp_code = generate_otp()
            otp_store = load_otp_store()
            otp_store[username] = otp_code
            save_otp_store(otp_store)

            session["pending_user"] = username

            receiver_email = users[username].get("email", "")
            email_sent, email_message = send_otp_email(receiver_email, username, otp_code)

            if email_sent:
                session["otp_delivery_message"] = f"OTP sent to {receiver_email}."
            else:
                # Development fallback when SMTP is not configured.
                print(f"[OTP FALLBACK] {username}: {otp_code}")
                session["otp_delivery_message"] = f"{email_message} Using terminal OTP fallback for testing."

            return redirect("/otp")

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
            session.pop("pending_user", None)
            return render_template("main.html", username=username)

        return render_template(
            "otp.html",
            username=username,
            delivery_message=session.get("otp_delivery_message", ""),
            error_message="Invalid OTP. Please try again.",
        )

    return render_template(
        "otp.html",
        username=username,
        delivery_message=session.get("otp_delivery_message", ""),
        error_message=None,
    )

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
