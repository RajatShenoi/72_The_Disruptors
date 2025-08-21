from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import User, Queries, db
from werkzeug.security import generate_password_hash, check_password_hash

import subprocess
import tempfile
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your-very-secure-secret-key'

db.init_app(app)
login_manager = LoginManager(app)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))

# Home route
@app.route('/')
def home():
    return render_template("home.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')

        if not email or not password:
            flash('Email and password required.')
            return redirect(url_for('register'))
        
        if db.session.query(User).filter_by(email=email).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        
        new_user = User(
            email=email, 
            hashed_password=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')

        user = db.session.query(User).filter_by(email=email).first()
        if user and check_password_hash(user.hashed_password, password):
            login_user(user)
            flash('Login successful.')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('home'))

@app.route('/analyse', methods=['POST'])
def analyse():
    url = request.form.get('url')
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmpfile:
        tmpfile_path = tmpfile.name

    CATEGORIES = [
        'accessibility',
        'best-practices',
        'performance',
        'seo'
    ]

    # Run Lighthouse CLI
    subprocess.run([
        'lighthouse',
        url,
        '--output=json',
        f'--output-path={tmpfile_path}',
        '--chrome-flags="--headless"'
    ], check=True)

    print("=" * 100)
    print("THIS IS THE TEMPFILE:", tmpfile_path)
    print("=" * 100)

    with open(tmpfile_path, 'r') as f:
        lighthouse_json = json.load(f)
        scores = {category: lighthouse_json['categories'][category]['score'] for category in CATEGORIES}
        
        # Extract audits, categories, and categoryGroups
        audits = lighthouse_json.get('audits', {})
        categories = lighthouse_json.get('categories', {})
        category_groups = lighthouse_json.get('categoryGroups', {})

        category_audits = {}

        def get_display(audit):
            mode = audit.get('scoreDisplayMode', '')
            score = audit.get('score')
            display_value = audit.get('displayValue', '')
            if mode == 'binary':
                return '✔️' if score == 1 else '❌'
            elif mode == 'numeric':
                return display_value if display_value else score
            elif mode == 'informative':
                return display_value
            elif mode == 'notApplicable':
                return 'Not Applicable'
            else:
                return display_value if display_value else score

        for cat_key, cat_obj in categories.items():
            cat_title = cat_obj.get('title', cat_key)
            audit_refs = cat_obj.get('auditRefs', [])
            cat_groups = {}

            for ref in audit_refs:
                audit_id = ref.get('id')
                group_id = ref.get('group')
                group_title = category_groups.get(group_id, {}).get('title', group_id) if group_id else None

                audit = audits.get(audit_id, {})
                audit_data = {
                    'title': audit.get('title', ''),
                    'description': audit.get('description', ''),
                    'score': audit.get('score'),
                    'scoreDisplayMode': audit.get('scoreDisplayMode', ''),
                    'displayValue': get_display(audit),
                    'details': audit.get('details', None)
                }

                if group_title:
                    if group_title not in cat_groups:
                        cat_groups[group_title] = []
                    cat_groups[group_title].append(audit_data)
                else:
                    if 'Ungrouped' not in cat_groups:
                        cat_groups['Ungrouped'] = []
                    cat_groups['Ungrouped'].append(audit_data)

            category_audits[cat_key] = {
                'title': cat_title,
                'groups': cat_groups
            }

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as zap_tmpfile:
            zap_tmpfile_path = zap_tmpfile.name

        zap_command = [
            '/Users/rajat/Dev/HackYugma/ZAP_2.16.1/zap.sh',
            '-cmd',
            '-quickurl', url,
            '-quickout', zap_tmpfile_path,
            '-quickprogress'
        ]

        subprocess.run(zap_command, check=True)

        with open(zap_tmpfile_path, 'r') as zap_file:
            zap_json = json.load(zap_file)
            
            severity_map = {
                "3": "High",
                "2": "Medium",
                "1": "Low",
                "0": "Informational"
            }
            alerts_by_severity = {
                "High": [],
                "Medium": [],
                "Low": [],
                "Informational": []
            }
            for site in zap_json.get("site", []):
                for alert in site.get("alerts", []):
                    severity = severity_map.get(alert.get("riskcode", "0"), "Informational")
                    alerts_by_severity[severity].append(alert)

        return render_template(
            "results.html", 
            scores=scores, 
            category_audits=category_audits,
            alerts_by_severity=alerts_by_severity,
            zap_json=zap_json,
        )

if __name__ == '__main__':
    app.run(debug=True)