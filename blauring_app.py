#!/usr/bin/env python3
"""
Blauring Verein - Ausgabenverwaltung
Flask Backend (Produktion via waitress hinter Apache-Reverse-Proxy)
"""

import os
import sqlite3
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, session
import csv
import io
from functools import wraps

app = Flask(__name__)

# --- Secret key: aus Datei laden oder erzeugen (nicht im Code hartkodieren) ---
SECRET_FILE = '/home/erch/.openclaw/workspace/state/blauring_secret.key'
os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
if os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, 'r') as fh:
        app.secret_key = fh.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(SECRET_FILE, 'w') as fh:
        fh.write(app.secret_key)
    os.chmod(SECRET_FILE, 0o600)

# --- Session-Cookie härten ---
app.config.update(
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,  # auf True stellen, sobald HTTPS aktiv ist
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
app.config['UPLOAD_FOLDER'] = '/home/erch/.openclaw/workspace/uploads'
app.config['DATABASE'] = '/home/erch/.openclaw/workspace/blauring.db'

# --- Passwort-Hashing: PBKDF2-HMAC-SHA256 mit Salt (Werkzeug) ---
from werkzeug.security import generate_password_hash, check_password_hash

PBKDF2_ITER = 260000

def hash_pw(password):
    """Neuer, sicherer Passwort-Hash."""
    return generate_password_hash(password, method='pbkdf2:sha256:%d' % PBKDF2_ITER)

def legacy_hash_pw(password, salt='blauring'):
    """Alter SHA-256-Hash (nur für Migration bestehender Konten)."""
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()

def verify_pw(stored_hash, password):
    """Prüft PBKDF2-Hash; akzeptiert übergangsweise alte SHA-256-Hashes."""
    if not stored_hash:
        return False
    if stored_hash.startswith(('pbkdf2:', 'scrypt:')):
        try:
            return check_password_hash(stored_hash, password)
        except Exception:
            return False
    # Legacy-Vergleich (konstantzeitig)
    return hmac.compare_digest(stored_hash, legacy_hash_pw(password))

# --- Einfaches Rate-Limiting für den Login (In-Memory) ---
LOGIN_ATTEMPTS = {}          # ip -> [timestamps]
LOGIN_MAX_ATTEMPTS = 8       # max. Versuche
LOGIN_WINDOW_SEC = 300       # innerhalb 5 Minuten
LOGIN_LOCK_SEC = 300         # danach 5 Minuten Sperre

def login_rate_ok(ip):
    now = time.time()
    attempts = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < LOGIN_WINDOW_SEC]
    LOGIN_ATTEMPTS[ip] = attempts
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        if now - attempts[-1] < LOGIN_LOCK_SEC:
            return False, int(LOGIN_LOCK_SEC - (now - attempts[-1]))
        LOGIN_ATTEMPTS[ip] = []
    return True, 0

def login_note_failure(ip):
    LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())

@app.after_request
def set_security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    return resp

def require_role(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = session.get('user')
            if not user or user.get('role') not in roles:
                return jsonify({'error': 'Nicht angemeldet oder keine Berechtigung'}), 401
            return fn(*args, **kwargs)
        return wrapper
    return deco

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db():
    """Get database connection (WAL + busy-timeout für parallele Zugriffe)."""
    db = sqlite3.connect(app.config['DATABASE'], timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA busy_timeout=10000')
    return db

def _year_code():
    """Zehner und Einer des aktuellen Jahres, z. B. 2026 -> '26'."""
    return str(datetime.now().year % 100).zfill(2)

def _read_setting(db, key):
    row = db.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
    return row['value'] if row else None

def _write_setting(db, key, value):
    db.execute('''
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    ''', (key, str(value)))

def _next_expense_id(db):
    """Nächste Buchungsnummer im Format JJ-XXXX erzeugen.

    Ein manuell gesetzter Startwert (settings.next_booking_no) hat Vorrang,
    sofern er höher ist als die höchste bereits vergebene Nummer des Jahres.
    """
    year = _year_code()
    rows = db.execute(
        "SELECT expense_id FROM expenses WHERE expense_id LIKE ?",
        (f'{year}-%',)
    ).fetchall()
    max_used = 0
    for r in rows:
        try:
            num = int(str(r['expense_id']).split('-')[-1])
        except (ValueError, AttributeError):
            continue
        max_used = max(max_used, num)
    try:
        manual_no = int(_read_setting(db, 'next_booking_no'))
    except (TypeError, ValueError):
        manual_no = 0
    next_no = max(max_used + 1, manual_no)
    return f'{year}-{str(next_no).zfill(4)}'

def init_db():
    """Initialize database with required tables"""
    db = get_db()
    
    # Users table
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('leiter', 'kassierer', 'admin')),
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Leaders table
    db.execute('''
        CREATE TABLE IF NOT EXISTS leaders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Expenses table
    db.execute('''
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            expense_id TEXT UNIQUE NOT NULL,
            date TEXT NOT NULL,
            description TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT 'Sonstiges',
            amount REAL NOT NULL,
            leader_id INTEGER NOT NULL,
            receipt_path TEXT,
            paid BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (leader_id) REFERENCES leaders(id)
        )
    ''')

    # Reasons (Anlässe) inkl. Budget
    db.execute('''
        CREATE TABLE IF NOT EXISTS reasons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reason TEXT UNIQUE NOT NULL,
            budget REAL NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Budget-Spalte bei bestehenden Installationen nachrüsten
    cols = [c['name'] for c in db.execute('PRAGMA table_info(reasons)').fetchall()]
    if 'budget' not in cols:
        db.execute('ALTER TABLE reasons ADD COLUMN budget REAL NOT NULL DEFAULT 0')

    # Einstellungen (z. B. nächste Buchungsnummer)
    db.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    
    # Seed default reasons
    default_reasons = ['Ausstattung', 'Veranstaltung', 'Reisen', 'Material', 'Sonstiges']
    for reason in default_reasons:
        try:
            db.execute('INSERT INTO reasons (reason) VALUES (?)', (reason,))
        except sqlite3.IntegrityError:
            pass

    # Seed demo users (username, role, name)
    demo_users = [
        ('paula', 'leiter', 'Paula Muster'),
        ('marc', 'leiter', 'Marc Beispiel'),
        ('kassier', 'kassierer', 'Kassier Verein'),
    ]
    for username, role, name in demo_users:
        try:
            db.execute(
                'INSERT INTO users (username, password_hash, role, name) VALUES (?, ?, ?, ?)',
                (username, hash_pw('demo123'), role, name)
            )
        except sqlite3.IntegrityError:
            pass

    # Seed leaders linked to the leiter users
    for username in ('paula', 'marc'):
        row = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if not row:
            continue
        uid = row['id']
        exists = db.execute('SELECT id FROM leaders WHERE user_id = ?', (uid,)).fetchone()
        if not exists:
            first, last = ('Paula', 'Muster') if username == 'paula' else ('Marc', 'Beispiel')
            db.execute(
                'INSERT INTO leaders (user_id, first_name, last_name, email) VALUES (?, ?, ?, ?)',
                (uid, first, last, f'{username}@blauring.local')
            )

    db.commit()
    db.close()

# Initialize database on startup
with app.app_context():
    init_db()

WORKDIR = '/home/erch/.openclaw/workspace'

@app.route('/')
def index():
    """Serve the login page"""
    return send_from_directory(WORKDIR, 'blauring-login.html')

@app.route('/login')
def login_page():
    return send_from_directory(WORKDIR, 'blauring-login.html')

@app.route('/dashboard')
def dashboard_page():
    return send_from_directory(WORKDIR, 'blauring-dashboard.html')

@app.route('/kassier')
def kassier_page():
    return send_from_directory(WORKDIR, 'blauring-kassier.html')

@app.route('/admin')
def admin_page():
    return send_from_directory(WORKDIR, 'blauring-admin.html')

@app.route('/healthz')
def healthz():
    return jsonify({'status': 'ok'})

@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint (gehärtet: Rate-Limit, PBKDF2, Migration)"""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
    ok, wait = login_rate_ok(ip)
    if not ok:
        return jsonify({'error': f'Zu viele Fehlversuche. Bitte {wait} s warten.'}), 429

    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Benutzername und Passwort erforderlich'}), 400

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    if not user or not verify_pw(user['password_hash'], password):
        db.close()
        login_note_failure(ip)
        return jsonify({'error': 'Ungültige Anmeldedaten'}), 401

    # Legacy-Hash automatisch auf PBKDF2 migrieren
    if not user['password_hash'].startswith(('pbkdf2:', 'scrypt:')):
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hash_pw(password), user['id']))
        db.commit()
    db.close()

    session.permanent = True
    session['user'] = {
        'user_id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'name': user['name']
    }

    return jsonify(session['user'])

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Abgemeldet'})

@app.route('/api/me', methods=['GET'])
def me():
    user = session.get('user')
    if not user:
        return jsonify({'error': 'Nicht angemeldet'}), 401
    return jsonify(user)

@app.route('/api/leaders', methods=['GET'])
def get_leaders():
    """Get list of all leaders"""
    db = get_db()
    leaders = db.execute('''
        SELECT l.id, l.first_name, l.last_name, l.email, l.phone, u.role, u.username
        FROM leaders l 
        JOIN users u ON l.user_id = u.id 
        ORDER BY l.last_name, l.first_name
    ''').fetchall()
    db.close()
    
    return jsonify([{
        'id': l['id'],
        'name': f"{l['first_name']} {l['last_name']}",
        'first_name': l['first_name'],
        'last_name': l['last_name'],
        'email': l['email'],
        'phone': l['phone'],
        'role': l['role'],
        'username': l['username']
    } for l in leaders])

@app.route('/api/leaders', methods=['POST'])
@require_role('kassierer', 'admin')
def add_leader():
    """Create a new leader (user + leader record)"""
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or 'demo123'
    first_name = (data.get('first_name') or '').strip()
    last_name = (data.get('last_name') or '').strip()
    email = (data.get('email') or '').strip()
    phone = (data.get('phone') or '').strip()
    role = data.get('role') or 'leiter'

    if not username or not first_name or not last_name:
        return jsonify({'error': 'Benutzername, Vorname und Nachname erforderlich'}), 400
    if role not in ('leiter', 'kassierer', 'admin'):
        return jsonify({'error': 'Ungültige Rolle'}), 400

    db = get_db()
    try:
        cur = db.execute(
            'INSERT INTO users (username, password_hash, role, name) VALUES (?, ?, ?, ?)',
            (username, hash_pw(password), role, f'{first_name} {last_name}')
        )
        uid = cur.lastrowid
        db.execute(
            'INSERT INTO leaders (user_id, first_name, last_name, email, phone) VALUES (?, ?, ?, ?, ?)',
            (uid, first_name, last_name, email, phone)
        )
        db.commit()
        db.close()
        return jsonify({'message': 'Leiter erstellt', 'user_id': uid}), 201
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'error': 'Benutzername existiert bereits'}), 409

@app.route('/api/leaders/<int:leader_id>', methods=['DELETE'])
@require_role('kassierer', 'admin')
def delete_leader(leader_id):
    """Delete a leader and its linked user"""
    db = get_db()
    row = db.execute('SELECT user_id FROM leaders WHERE id = ?', (leader_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'Leiter nicht gefunden'}), 404
    used = db.execute('SELECT COUNT(*) AS c FROM expenses WHERE leader_id = ?', (leader_id,)).fetchone()['c']
    if used:
        db.close()
        return jsonify({'error': f'Leiter hat {used} Ausgaben und kann nicht gelöscht werden'}), 409
    uid = row['user_id']
    db.execute('DELETE FROM leaders WHERE id = ?', (leader_id,))
    db.execute('DELETE FROM users WHERE id = ?', (uid,))
    db.commit()
    db.close()
    return jsonify({'message': 'Leiter gelöscht'})

@app.route('/api/expenses', methods=['GET'])
def get_expenses():
    """Get all expenses with leader info"""
    db = get_db()
    expenses = db.execute('''
        SELECT e.*, 
               l.first_name || ' ' || l.last_name as leader_name,
               l.first_name as leader_first_name,
               l.last_name as leader_last_name
        FROM expenses e
        LEFT JOIN leaders l ON e.leader_id = l.id
        ORDER BY e.date DESC, e.id DESC
    ''').fetchall()
    db.close()
    
    return jsonify([{
        'id': e['id'],
        'expense_id': e['expense_id'],
        'date': e['date'],
        'description': e['description'],
        'reason': e['reason'],
        'amount': e['amount'],
        'leader_id': e['leader_id'],
        'leader_name': e['leader_name'],
        'receipt': ('/uploads/' + e['receipt_path'].split('/')[-1]) if e['receipt_path'] else None,
        'paid': bool(e['paid'])
    } for e in expenses])

@app.route('/api/expenses', methods=['POST'])
def add_expense():
    """Add new expense"""
    data = request.get_json()

    db = get_db()

    # Nächste Buchungsnummer: manuell gesetzter Zähler hat Vorrang,
    # sonst fortlaufend aus hoechster vorhandener Nummer ableiten.
    expense_id = _next_expense_id(db)

    # Insert expense
    cursor = db.execute('''
        INSERT INTO expenses (expense_id, date, description, reason, amount, leader_id, receipt_path, paid)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        expense_id,
        data.get('date', datetime.now().strftime('%Y-%m-%d')),
        data.get('description', ''),
        data.get('reason', 'Sonstiges'),
        float(data.get('amount', 0)),
        int(data.get('leader_id', 0)),
        data.get('receipt') or None,
        False
    ))

    db.commit()
    new_id = cursor.lastrowid
    db.close()

    return jsonify({
        'id': new_id,
        'expense_id': expense_id,
        'message': 'Expense added successfully'
    }), 201

@app.route('/api/expenses/<int:id>', methods=['PATCH'])
def update_expense(id):
    """Update expense (e.g., mark as paid)"""
    data = request.get_json()
    
    db = get_db()
    db.execute('''
        UPDATE expenses SET paid = ? WHERE id = ?
    ''', (data.get('paid', True), id))
    db.commit()
    db.close()
    
    return jsonify({'message': 'Expense updated'})

@app.route('/api/expenses/<int:id>', methods=['DELETE'])
@require_role('kassierer', 'admin')
def delete_expense(id):
    """Delete a single expense entry"""
    db = get_db()
    row = db.execute('SELECT expense_id FROM expenses WHERE id = ?', (id,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'Buchung nicht gefunden'}), 404
    db.execute('DELETE FROM expenses WHERE id = ?', (id,))
    db.commit()
    db.close()
    return jsonify({'message': f'Buchung {row["expense_id"] or id} gelöscht'})

@app.route('/api/settings/booking', methods=['GET'])
@require_role('kassierer', 'admin')
def get_booking_setting():
    """Nächste Buchungsnummer (Startwert) + Format-Info"""
    db = get_db()
    year = _year_code()
    rows = db.execute(
        "SELECT expense_id FROM expenses WHERE expense_id LIKE ?", (f'{year}-%',)
    ).fetchall()
    max_used = 0
    for r in rows:
        try:
            max_used = max(max_used, int(str(r['expense_id']).split('-')[-1]))
        except (ValueError, AttributeError):
            continue
    manual = _read_setting(db, 'next_booking_no')
    db.close()
    try:
        manual_no = int(manual)
    except (TypeError, ValueError):
        manual_no = None
    m = manual_no if isinstance(manual_no, int) and manual_no > 0 else 0
    next_no = max(max_used + 1, m)
    return jsonify({
        'year': year,
        'year_full': datetime.now().year,
        'max_used': max_used,
        'manual_next': manual_no,
        'next_no': next_no,
        'next_expense_id': f'{year}-{str(next_no).zfill(4)}'
    })

@app.route('/api/settings/booking', methods=['PUT'])
@require_role('kassierer', 'admin')
def set_booking_setting():
    """Startwert der nächsten Buchungsnummer setzen (nur erhöhen)."""
    data = request.get_json(silent=True) or {}
    try:
        nxt = int(data.get('next_booking_no'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Ungültige Nummer'}), 400
    if nxt < 1:
        return jsonify({'error': 'Nummer muss mindestens 1 sein'}), 400

    db = get_db()
    year = _year_code()
    rows = db.execute(
        "SELECT expense_id FROM expenses WHERE expense_id LIKE ?", (f'{year}-%',)
    ).fetchall()
    max_used = 0
    for r in rows:
        try:
            max_used = max(max_used, int(str(r['expense_id']).split('-')[-1]))
        except (ValueError, AttributeError):
            continue
    if nxt <= max_used:
        db.close()
        return jsonify({'error': f'Nummer muss größer als die höchste vergebene ({max_used}) sein'}), 409
    _write_setting(db, 'next_booking_no', nxt)
    db.commit()
    db.close()
    return jsonify({'message': f'Nächste Buchungsnummer auf {year}-{str(nxt).zfill(4)} gesetzt'})

@app.route('/api/reasons', methods=['GET'])
def get_reasons():
    """Get all reasons with budget"""
    db = get_db()
    rows = db.execute('SELECT reason, budget FROM reasons ORDER BY reason').fetchall()
    db.close()
    return jsonify([{'reason': r['reason'], 'budget': r['budget'] or 0} for r in rows])

@app.route('/api/reasons', methods=['POST'])
@require_role('kassierer', 'admin')
def add_reason():
    """Add new reason (with optional budget)"""
    data = request.get_json(silent=True) or {}
    reason = (data.get('reason') or '').strip()
    try:
        budget = float(data.get('budget') or 0)
    except (TypeError, ValueError):
        budget = 0

    if not reason:
        return jsonify({'error': 'Anlass erforderlich'}), 400

    db = get_db()
    try:
        db.execute('INSERT INTO reasons (reason, budget) VALUES (?, ?)', (reason, budget))
        db.commit()
        db.close()
        return jsonify({'message': 'Anlass hinzugefügt'}), 201
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'error': 'Anlass existiert bereits'}), 409

@app.route('/api/reasons/<path:reason>', methods=['PUT'])
@require_role('kassierer', 'admin')
def update_reason(reason):
    """Set/update the budget of a reason"""
    data = request.get_json(silent=True) or {}
    try:
        budget = float(data.get('budget') or 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'Ungültiges Budget'}), 400
    if budget < 0:
        return jsonify({'error': 'Budget darf nicht negativ sein'}), 400
    db = get_db()
    row = db.execute('SELECT id FROM reasons WHERE reason = ?', (reason,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'Anlass nicht gefunden'}), 404
    db.execute('UPDATE reasons SET budget = ? WHERE reason = ?', (budget, reason))
    db.commit()
    db.close()
    return jsonify({'message': f'Budget für „{reason}" gespeichert'})

@app.route('/api/reasons/<path:reason>', methods=['DELETE'])
@require_role('kassierer', 'admin')
def delete_reason(reason):
    """Delete a reason"""
    db = get_db()
    used = db.execute('SELECT COUNT(*) AS c FROM expenses WHERE reason = ?', (reason,)).fetchone()['c']
    if used:
        db.close()
        return jsonify({'error': f'Anlass wird in {used} Ausgaben verwendet'}), 409
    db.execute('DELETE FROM reasons WHERE reason = ?', (reason,))
    db.commit()
    db.close()
    return jsonify({'message': 'Anlass gelöscht'})

@app.route('/api/export', methods=['GET'])
def export_expenses():
    """Export expenses to CSV (Excel-compatible)"""
    db = get_db()
    expenses = db.execute('''
        SELECT e.expense_id, e.date, l.first_name || ' ' || l.last_name as leader,
               e.description, e.reason, e.amount, 
               CASE WHEN e.paid = 1 THEN 'Bezahlt' ELSE 'Offen' END as status
        FROM expenses e
        LEFT JOIN leaders l ON e.leader_id = l.id
        ORDER BY e.date DESC
    ''').fetchall()
    db.close()
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Datum', 'Leiter', 'Beschreibung', 'Anlass', 'Betrag (CHF)', 'Status'])
    
    for e in expenses:
        writer.writerow([
            e['expense_id'],
            e['date'],
            e['leader'] or 'Unbekannt',
            e['description'],
            e['reason'],
            f"{e['amount']:.2f}",
            e['status']
        ])
    
    output.seek(0)
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment;filename=blauring_ausgaben.csv'
    }

@app.route('/uploads/<path:filename>')
@require_role('leiter', 'kassierer', 'admin')
def serve_upload(filename):
    """Quittung/Beleg ausliefern (nur für angemeldete Benutzer)."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/upload', methods=['POST'])
@require_role('leiter', 'kassierer', 'admin')
def upload_receipt():
    """Upload receipt image"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Optional: Datei unter der Buchungsnummer benennen (z. B. 26-0001.jpg)
    booking_no = (request.form.get('booking_no') or '').strip()
    ext = os.path.splitext(file.filename)[1].lower() or '.jpg'
    if ext not in ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.heic'):
        ext = '.jpg'

    if booking_no:
        safe = ''.join(c for c in booking_no if c.isalnum() or c in ('-', '_'))
        filename = f"{safe}{ext}" if safe else f"{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
    else:
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    return jsonify({
        'filename': filename,
        'path': '/uploads/' + filename
    })

if __name__ == '__main__':
    # Produktion: waitress (kein Debug-Server, kein Auto-Reload)
    if os.environ.get('BLAURING_DEV') == '1':
        app.run(host='127.0.0.1', port=5000, debug=True)
    else:
        from waitress import serve
        serve(app, host='0.0.0.0', port=5000, threads=8)