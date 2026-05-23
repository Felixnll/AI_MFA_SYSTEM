from flask import Flask, render_template, request, redirect, session, jsonify
import json
import os
from pathlib import Path
import random
import smtplib
import ssl
from email.mime.text import MIMEText
from datetime import datetime
import hashlib
import statistics
import csv
import traceback

# Lazy-friendly imports for optional ML dependencies
try:
    import numpy as np
except Exception:
    np = None

try:
    from joblib import load as _joblib_load
except Exception:
    _joblib_load = None
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
MODEL_PATH = Path("models/risk_model.joblib")
RISK_MODEL = None
MODEL_MANAGER = None

login_tracker = {}

def load_users():
    """Load users from JSON database"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_users(users):
    """Persist users database to JSON file."""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def update_user_login_hour(username, hour, max_history=100):
    """Record a successful login hour for a user (keeps recent `max_history` entries)."""
    users = load_users()
    if username not in users:
        return
    user = users[username]
    if "login_hours" not in user or not isinstance(user.get("login_hours"), list):
        user["login_hours"] = []
    try:
        user["login_hours"].append(int(hour))
    except Exception:
        pass
    # Trim history to last N entries
    if len(user["login_hours"]) > max_history:
        user["login_hours"] = user["login_hours"][-max_history:]
    users[username] = user
    save_users(users)


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


def extract_features(username, user_record, password_match, device_id, override_unusual_hour=None):
    """Extract simple login risk features.

    Now accepts device/ip/typing context provided by the caller via optional
    keyword args supplied on the call sites.
    """
    # Backwards-compatible entry: callers may pass additional kwargs in request
    # handling (ip_address, typing_time_ms). We expect callers to pass those.
    state = get_login_state(username)
    current_time = time.time()
    last_attempt_time = state.get("last_attempt_time")
    short_interval = last_attempt_time is not None and (current_time - last_attempt_time) < 5
    # Determine whether this login attempt occurs at an unusual hour for this user.
    # We keep a simple historic per-user hour histogram (`login_hours`) and
    # mark as unusual when the current hour isn't among the user's typical hours.
    current_hour = datetime.now().hour
    login_hours = user_record.get("login_hours", []) if user_record else []
    unusual_hour = False
    if login_hours and len(login_hours) >= 3:
        # build counts per hour
        counts = {h: 0 for h in range(24)}
        for h in login_hours:
            try:
                counts[int(h)] += 1
            except Exception:
                continue
        max_count = max(counts.values()) if counts else 0
        # typical hours are those with at least 20% of the max count (tunable)
        if max_count > 0:
            typical_hours = {h for h, c in counts.items() if c >= max(1, int(0.2 * max_count))}
            unusual_hour = current_hour not in typical_hours
    else:
        # Not enough history to judge; treat as not unusual to avoid false positives
        unusual_hour = False

    # Demo-only override for presentation/testing.
    if override_unusual_hour is not None:
        unusual_hour = bool(override_unusual_hour)

    unknown_device = device_id.strip() != user_record.get("known_device", "") if user_record else True

    # IP risk: flag when the IP is not in the user's known_ips list
    ip_address = None
    typing_time_ms = None
    try:
        # Expect caller to have set these temporarily on the state dict or passed via globals
        ip_address = state.get('_ip_address')
        typing_time_ms = state.get('_typing_time_ms')
    except Exception:
        ip_address = None

    known_ips = user_record.get('known_ips', []) if user_record else []
    ip_risk = False
    if ip_address:
        ip_risk = ip_address not in known_ips

    # Typing speed anomaly: compare submitted typing_time_ms to historical median
    typing_speed_anomaly = False
    try:
        typing_hist = user_record.get('typing_times', []) if user_record else []
        if typing_time_ms is not None and typing_hist:
            med = statistics.median(typing_hist)
            # anomalous if >2x slower or <0.5x faster than median
            if med > 0 and (typing_time_ms > 2 * med or typing_time_ms < 0.5 * med):
                typing_speed_anomaly = True
        else:
            typing_speed_anomaly = False
    except Exception:
        typing_speed_anomaly = False

    return {
        "failed_attempts": state["failed_attempts"],
        "short_interval": short_interval,
        "unknown_device": unknown_device,
        "unusual_hour": unusual_hour,
        "password_match": password_match,
        "ip_risk": ip_risk,
        "typing_speed_anomaly": typing_speed_anomaly,
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
    if features.get('ip_risk'):
        score += 1
    if features.get('typing_speed_anomaly'):
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


def build_mitigation_summary(features=None, risk_level=None, captcha_required=False, blocked=False):
    """Return human-readable mitigation items for the current login attempt."""
    items = []
    features = features or {}

    items.append("Password + OTP multi-factor authentication")

    if captcha_required:
        items.append("CAPTCHA after 2 failed attempts")

    if features.get('ip_risk'):
        items.append("IP address tracking and unknown-IP flagging")

    if features.get('typing_speed_anomaly'):
        items.append("Behavioral biometrics via typing-speed anomaly detection")

    if features.get('unknown_device'):
        items.append("Unknown device detection")

    if features.get('short_interval'):
        items.append("Short-interval retry detection")

    if features.get('unusual_hour'):
        items.append("Unusual-hour login detection")

    if risk_level == 'medium':
        items.append("3-second delay before OTP delivery")

    if risk_level == 'high' or blocked:
        items.append("60-second temporary account block")

    return items


class ModelManager:
    """Manage loading and predicting with the risk model, with automatic reload when file changes."""
    def __init__(self, path: Path):
        self.path = path
        self.model = None
        self.mtime = None

    def load(self):
        try:
            if not self.path.exists():
                self.model = None
                self.mtime = None
                return False
            mtime = self.path.stat().st_mtime
            if self.model is not None and self.mtime == mtime:
                return True
            # attempt to load via joblib
            if _joblib_load is not None:
                self.model = _joblib_load(self.path)
            else:
                import joblib
                self.model = joblib.load(self.path)
            self.mtime = mtime
            print(f"Loaded risk model from {self.path}")
            return True
        except Exception as e:
            print(f"Failed to load model: {e}")
            self.model = None
            self.mtime = None
            return False

    def predict(self, features: dict):
        """Return (label, confidence) or (None, 0.0) if unavailable."""
        if self.model is None or np is None:
            return None, 0.0
        try:
            arr = np.array([[
                features.get('failed_attempts', 0),
                1 if features.get('short_interval') else 0,
                1 if features.get('unknown_device') else 0,
                1 if features.get('unusual_hour') else 0,
                1 if features.get('password_match') else 0,
                1 if features.get('ip_risk') else 0,
                1 if features.get('typing_speed_anomaly') else 0,
            ]])
            # auto-reload if file changed
            try:
                if self.path.exists():
                    mtime = self.path.stat().st_mtime
                    if self.mtime != mtime:
                        self.load()
            except Exception:
                pass
            probs = self.model.predict_proba(arr)[0]
            idx = int(np.argmax(probs))
            label = {0: 'low', 1: 'medium', 2: 'high'}.get(idx, 'low')
            confidence = float(probs[idx])
            return label, confidence
        except Exception as e:
            print(f"Model prediction error: {e}")
            return None, 0.0


def predict_risk_ml(features):
    global MODEL_MANAGER
    if MODEL_MANAGER is None:
        MODEL_MANAGER = ModelManager(MODEL_PATH)
        MODEL_MANAGER.load()
    return MODEL_MANAGER.predict(features)


def log_feature_vector(features, label):
    """Append feature vector and label to CSV for future training.

    Columns: failed_attempts, short_interval, unknown_device, unusual_hour, password_match, label
    """
    try:
        import csv
        header = ['failed_attempts','short_interval','unknown_device','unusual_hour','password_match','ip_risk','typing_speed_anomaly','label']
        file_path = Path('training_data.csv')
        write_header = not file_path.exists()
        with open(file_path, 'a', newline='') as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(header)
            writer.writerow([
                features.get('failed_attempts',0),
                1 if features.get('short_interval') else 0,
                1 if features.get('unknown_device') else 0,
                1 if features.get('unusual_hour') else 0,
                1 if features.get('password_match') else 0,
                1 if features.get('ip_risk') else 0,
                1 if features.get('typing_speed_anomaly') else 0,
                label,
            ])
    except Exception:
        pass


# File to persist ML prediction events (JSON lines)
PREDICTION_LOG = Path('ml_predictions.jsonl')


def write_ml_prediction(record: dict):
    """Append a JSON record describing an ML prediction to the predictions log.

    Record is expected to be JSON-serializable.
    """
    try:
        with open(PREDICTION_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, default=str) + '\n')
    except Exception:
        # keep logging best-effort; avoid raising in request path
        print("Failed to write prediction log:\n", traceback.format_exc())


def read_recent_predictions(n=100):
    """Read up to `n` most recent prediction records from the JSON-lines log."""
    try:
        if not PREDICTION_LOG.exists():
            return []
        with open(PREDICTION_LOG, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        lines = [l.strip() for l in lines if l.strip()]
        lines = lines[-n:]
        return [json.loads(l) for l in lines]
    except Exception:
        return []


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
        demo_unusual_hour = request.form.get("demo_unusual_hour") == "on"
        # Capture typing time (ms) sent by client-side JS; optional
        typing_time_raw = request.form.get('typing_time_ms')
        try:
            typing_time_ms = float(typing_time_raw) if typing_time_raw is not None and typing_time_raw != '' else None
        except Exception:
            typing_time_ms = None
        # Capture client IP (best-effort)
        ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
        
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
        
        # If user has accumulated failures, require CAPTCHA input
        if username in users:
            state_tmp = get_login_state(username)
            if state_tmp.get('failed_attempts', 0) >= 2:
                # Ensure captcha answer exists and matches
                submitted = request.form.get('captcha', '').strip()
                expected = session.get('captcha_answer')
                if expected is None or submitted == '':
                    # generate a simple math captcha and prompt user
                    a = random.randint(2, 9)
                    b = random.randint(2, 9)
                    session['captcha_question'] = f"What is {a} + {b}?"
                    session['captcha_answer'] = str(a + b)
                    return render_template('login.html', error_message='Please answer the CAPTCHA to continue.', show_captcha=True, captcha_question=session.get('captcha_question'))
                if submitted != str(expected):
                    return render_template('login.html', error_message='CAPTCHA incorrect. Try again.', show_captcha=True, captcha_question=session.get('captcha_question'))

        # Validate credentials against database
        stored_pw = users.get(username, {}).get('password')
        # Support legacy plaintext and migrated hashed values
        def verify_pw(plain, stored):
            if stored is None:
                return False
            if '$' in stored:
                salt, hexhash = stored.split('$',1)
                h = hashlib.sha256((salt + plain).encode('utf-8')).hexdigest()
                return h == hexhash
            return plain == stored

        if username in users and verify_pw(password, stored_pw):
            state = get_login_state(username)
            state["last_attempt_time"] = time.time()
            # attach transient context for IP and typing data
            state['_ip_address'] = ip_addr
            state['_typing_time_ms'] = typing_time_ms
            features = extract_features(username, users[username], True, device_id, override_unusual_hour=demo_unusual_hour)
            # Try ML model first; fall back to rule-based engine when model unavailable or low-confidence
            ml_label, ml_conf = predict_risk_ml(features)
            if ml_label and ml_conf >= 0.60:
                risk_level = ml_label
                # use confidence as a proxy for score (scaled)
                risk_score = int(ml_conf * 10)
            else:
                risk_level, risk_score = simple_risk_engine(features)

            # Record this prediction event for admin review
            try:
                rule_label_tmp, rule_score_tmp = simple_risk_engine(features)
                write_ml_prediction({
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'source': 'login_success',
                    'username': username,
                    'features': features,
                    'ml_label': ml_label,
                    'ml_confidence': ml_conf,
                    'rule_label': rule_label_tmp,
                    'rule_score': rule_score_tmp,
                })
            except Exception:
                pass

            # Log features + simple_label for future training
            try:
                simple_label, _ = simple_risk_engine(features)
                label_map = {'low': 0, 'medium': 1, 'high': 2}
                log_feature_vector(features, label_map.get(simple_label, 0))
            except Exception:
                pass

            session["risk_level"] = risk_level
            session["risk_score"] = risk_score
            session["mitigation_summary"] = build_mitigation_summary(
                features,
                risk_level=risk_level,
                blocked=(risk_level == 'high'),
            )

            if risk_level == "high":
                state["blocked_until"] = time.time() + 60
                return render_template(
                    "access_denied.html",
                    username=username,
                    denial_type="blocked",
                    remaining_seconds=60,
                    reason="High-risk login detected. Access temporarily blocked for 60 seconds.",
                    mitigation_summary=session.get("mitigation_summary", []),
                )

            if risk_level == "medium":
                # For medium risk, require a short client-visible delay before OTP verification.
                # Store the delay end timestamp in session so the OTP page can show a countdown.
                session["delay_until"] = time.time() + 3

            state["failed_attempts"] = 0
            state["blocked_until"] = 0

            # Update user's known IPs and typing history
            try:
                u = users.get(username, {})
                if 'known_ips' not in u or not isinstance(u.get('known_ips'), list):
                    u['known_ips'] = []
                if ip_addr and ip_addr not in u['known_ips']:
                    u['known_ips'].append(ip_addr)
                if 'typing_times' not in u or not isinstance(u.get('typing_times'), list):
                    u['typing_times'] = []
                if typing_time_ms is not None:
                    u['typing_times'].append(float(typing_time_ms))
                    # limit history
                    if len(u['typing_times']) > 200:
                        u['typing_times'] = u['typing_times'][-200:]
                users[username] = u
                save_users(users)
            except Exception:
                pass

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
            # attach IP and typing to state for feature extraction
            state['_ip_address'] = ip_addr
            state['_typing_time_ms'] = typing_time_ms

            # After two failed attempts, force a CAPTCHA before doing anything else.
            if state["failed_attempts"] >= 2:
                a = random.randint(2, 9)
                b = random.randint(2, 9)
                session['captcha_question'] = f"What is {a} + {b}?"
                session['captcha_answer'] = str(a + b)
                return render_template(
                    'login.html',
                    error_message='Please solve the CAPTCHA to continue.',
                    show_captcha=True,
                    captcha_question=session.get('captcha_question'),
                    mitigation_summary=build_mitigation_summary(
                        captcha_required=True,
                    ),
                )

            features = extract_features(username, users[username], False, device_id, override_unusual_hour=demo_unusual_hour)
            # Try ML model for failed attempts as well
            ml_label, ml_conf = predict_risk_ml(features)
            if ml_label and ml_conf >= 0.60:
                risk_level = ml_label
                risk_score = int(ml_conf * 10)
            else:
                risk_level, risk_score = simple_risk_engine(features)

            # Log features (label from rule engine)
            try:
                simple_label, _ = simple_risk_engine(features)
                label_map = {'low': 0, 'medium': 1, 'high': 2}
                log_feature_vector(features, label_map.get(simple_label, 0))
            except Exception:
                pass

            # Record prediction event for failed attempt
            try:
                rule_label_tmp, rule_score_tmp = simple_risk_engine(features)
                write_ml_prediction({
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'source': 'login_failed_attempt',
                    'username': username,
                    'features': features,
                    'ml_label': ml_label,
                    'ml_confidence': ml_conf,
                    'rule_label': rule_label_tmp,
                    'rule_score': rule_score_tmp,
                })
            except Exception:
                pass

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
            # Record this successful login hour for the user
            try:
                update_user_login_hour(username, datetime.now().hour)
            except Exception:
                pass

            # Clear pending session keys related to verification/delay
            session.pop("pending_user", None)
            session.pop("delay_until", None)
            session.pop("otp_warning_message", None)
            session.pop("otp_delivery_message", None)
            return render_template(
                "main.html",
                username=username,
                risk_level=session.get("risk_level", "unknown"),
                mitigation_summary=session.get("mitigation_summary", []),
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
        mitigation_summary=session.get("mitigation_summary", []),
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


@app.route('/ml_status', methods=['GET'])
def ml_status():
    """Return ML availability and model status."""
    global MODEL_MANAGER
    numpy_available = np is not None
    model_loaded = False
    info = {
        'ml_enabled': False,
        'model_loaded': False,
        'numpy_available': numpy_available,
        'model_path': str(MODEL_PATH) if MODEL_PATH.exists() else None,
    }
    if MODEL_MANAGER is None:
        MODEL_MANAGER = ModelManager(MODEL_PATH)
        MODEL_MANAGER.load()
    model_loaded = MODEL_MANAGER.model is not None
    info['model_loaded'] = model_loaded
    info['ml_enabled'] = model_loaded and numpy_available
    if model_loaded:
        try:
            mdl = MODEL_MANAGER.model
            info['classes'] = getattr(mdl, 'classes_', None).tolist() if hasattr(mdl, 'classes_') else None
            info['feature_importances'] = getattr(mdl, 'feature_importances_', None).tolist() if hasattr(mdl, 'feature_importances_') else None
            info['model_mtime'] = MODEL_MANAGER.mtime
        except Exception:
            pass
    return jsonify(info)


@app.route('/admin/ml_reload', methods=['POST'])
def admin_ml_reload():
    """Force reload the ML model from disk."""
    global MODEL_MANAGER
    if MODEL_MANAGER is None:
        MODEL_MANAGER = ModelManager(MODEL_PATH)
    ok = MODEL_MANAGER.load()
    return jsonify({'reloaded': ok, 'model_loaded': MODEL_MANAGER.model is not None})


def format_features(f):
    # Ensure feature dict contains expected keys and types
    return {
        'failed_attempts': int(f.get('failed_attempts', 0)),
        'short_interval': bool(f.get('short_interval', False)),
        'unknown_device': bool(f.get('unknown_device', False)),
        'unusual_hour': bool(f.get('unusual_hour', False)),
        'password_match': bool(f.get('password_match', False)),
        'ip_risk': bool(f.get('ip_risk', False)),
        'typing_speed_anomaly': bool(f.get('typing_speed_anomaly', False)),
    }


@app.route('/ml_samples', methods=['GET'])
def ml_samples():
    """Return ML and rule-based predictions for representative sample inputs."""
    samples = [
        ("low", {"failed_attempts": 0, "short_interval": False, "unknown_device": False, "unusual_hour": False, "password_match": True}),
        ("low_unusual_hour", {"failed_attempts": 0, "short_interval": False, "unknown_device": False, "unusual_hour": True, "password_match": True}),
        ("medium_guess", {"failed_attempts": 1, "short_interval": True, "unknown_device": True, "unusual_hour": False, "password_match": True}),
        ("medium_wrong_pw", {"failed_attempts": 2, "short_interval": False, "unknown_device": True, "unusual_hour": False, "password_match": False}),
        ("high_wrong_pw", {"failed_attempts": 3, "short_interval": True, "unknown_device": True, "unusual_hour": True, "password_match": False}),
        ("high_rapid_failures", {"failed_attempts": 5, "short_interval": True, "unknown_device": True, "unusual_hour": False, "password_match": False}),
        ("unknown_device_only", {"failed_attempts": 0, "short_interval": False, "unknown_device": True, "unusual_hour": False, "password_match": True}),
    ]

    out = []
    for name, feat in samples:
        feats = format_features(feat)
        # Ensure model manager is initialized and model loaded lazily when needed
        global MODEL_MANAGER
        if MODEL_MANAGER is None:
            MODEL_MANAGER = ModelManager(MODEL_PATH)
            try:
                MODEL_MANAGER.load()
            except Exception:
                pass
        ml_label, ml_conf = predict_risk_ml(feats)
        rule_label, rule_score = simple_risk_engine(feats)
        out.append({
            'name': name,
            'features': feats,
            'ml_label': ml_label,
            'ml_confidence': ml_conf,
            'rule_label': rule_label,
            'rule_score': rule_score,
        })
    return jsonify({'samples': out})


@app.route('/admin/ml_dashboard', methods=['GET'])
def admin_ml_dashboard():
    """Render a small admin dashboard showing recent ML prediction events."""
    try:
        preds = read_recent_predictions(200)
        # show most recent first
        preds = sorted(preds, key=lambda x: x.get('timestamp', ''), reverse=True)
    except Exception:
        preds = []
    return render_template('admin_ml_dashboard.html', predictions=preds)


@app.route('/ml_predict', methods=['POST'])
def ml_predict():
    """Accepts JSON with feature keys and returns ML + rule predictions.

    Expected JSON keys: failed_attempts, short_interval, unknown_device, unusual_hour, password_match
    """
    data = request.get_json(force=True, silent=True) or {}
    feats = format_features(data)
    # Lazy-load model manager if needed so importing the app doesn't require running as __main__
    global MODEL_MANAGER
    if MODEL_MANAGER is None:
        MODEL_MANAGER = ModelManager(MODEL_PATH)
        try:
            MODEL_MANAGER.load()
        except Exception:
            pass
    ml_label, ml_conf = predict_risk_ml(feats)
    rule_label, rule_score = simple_risk_engine(feats)
    # Persist prediction event for admin dashboard
    try:
        write_ml_prediction({
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'source': 'ml_predict_api',
            'username': session.get('pending_user'),
            'features': feats,
            'ml_label': ml_label,
            'ml_confidence': ml_conf,
            'rule_label': rule_label,
            'rule_score': rule_score,
        })
    except Exception:
        pass
    return jsonify({
        'features': feats,
        'ml_label': ml_label,
        'ml_confidence': ml_conf,
        'rule_label': rule_label,
        'rule_score': rule_score,
    })

# Attempt to load the ML model at import time so test clients and imported modules
# see ML availability without running the app as a script.
try:
    MODEL_MANAGER = ModelManager(MODEL_PATH)
    MODEL_MANAGER.load()
except Exception:
    pass

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    # Attempt to load ML model (optional)
    try:
        MODEL_MANAGER = ModelManager(MODEL_PATH)
        MODEL_MANAGER.load()
    except Exception:
        pass
    app.run(debug=True)
