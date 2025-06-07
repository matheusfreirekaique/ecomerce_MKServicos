import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask.cli import with_appcontext
import click

# Initialize Flask app
app = Flask(__name__)
app.config.from_pyfile('config.py')

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL'].replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {'sslmode': 'require'}
}

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Email Configuration
app.config.update(
    MAIL_SERVER='smtp.example.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@example.com')
)

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    can_view_products = db.Column(db.Boolean, default=True)
    reset_token = db.Column(db.String(100))
    reset_token_expires = db.Column(db.DateTime)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))  # Fixed to reference 'users.id'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    creator = db.relationship('User', backref='products', lazy=True)

# CLI Commands
@app.cli.command("init-db")
@with_appcontext
def init_db_command():
    """Initialize the database"""
    try:
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
        print("✅ Database initialized successfully!")
    except Exception as e:
        print(f"❌ Error initializing database: {str(e)}")
        raise

# Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Acesso restrito a administradores', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Helper Functions
def send_reset_email(user):
    try:
        token = secrets.token_urlsafe(32)
        user.reset_token = token
        user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        
        reset_url = url_for('reset_password', token=token, _external=True)
        
        msg = Message(
            '🔑 Redefinição de Senha',
            recipients=[user.email],
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        msg.body = f'''Olá {user.username},

Para redefinir sua senha, clique no link abaixo:
{reset_url}

*Link válido por 1 hora.*

Caso não tenha solicitado, ignore este e-mail.
'''
        mail.send(msg)
        return True
    except Exception as e:
        print(f"ERRO NO ENVIO: {str(e)}")
        db.session.rollback()
        return False

# Routes (keep all your existing routes exactly as they were)
# ... [All your existing route definitions remain unchanged] ...

# Initialize database before first request
with app.app_context():
    try:
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
    except Exception as e:
        print(f"⚠️ Database initialization error: {str(e)}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)