from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import User, Queries, db
from werkzeug.security import generate_password_hash, check_password_hash
from rq import Queue
from redis import Redis
from tasks import run_analysis_task

import json

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SECRET_KEY'] = 'your-very-secure-secret-key'
    db.init_app(app)
    return app

app = create_app()
login_manager = LoginManager(app)

redis_conn = Redis()
q = Queue(connection=redis_conn)

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

@app.route('/history')
@login_required
def history():
    user_queries = Queries.query.filter_by(user_id=current_user.id).order_by(Queries.created_at.desc()).all()
    return render_template('history.html', user_queries=user_queries)

@app.route('/saved_result')
@login_required
def saved_result():
    query_id = request.args.get('query_id')
    query = Queries.query.filter_by(id=query_id, user_id=current_user.id).first()
    if not query:
        flash('Query not found.')
        return redirect(url_for('history'))
    
    scores = json.loads(query.scores)
    category_audits = json.loads(query.performance)
    alerts_by_severity = json.loads(query.security)

    return render_template(
        "results.html", 
        scores=scores,
        category_audits=category_audits,
        alerts_by_severity=alerts_by_severity
    )

@app.route('/analyse', methods=['POST'])
@login_required
def analyse():
    url = request.form.get('url')
    new_query = Queries(
        user_id=current_user.id,
        url=url,
        status=3,  # 3 for queued
        scores="{}",
        performance="{}",
        security="{}"
    )
    db.session.add(new_query)
    db.session.commit()
    job = q.enqueue(run_analysis_task, new_query.id, url, job_timeout=1800)  # timeout in seconds
    flash('Your analysis has been queued and will be processed soon.')
    return redirect(url_for('history'))

if __name__ == '__main__':
    app.run(debug=True)