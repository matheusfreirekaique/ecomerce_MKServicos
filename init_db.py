from app import app, db
from models import User  # type: ignore # Ajuste conforme sua estrutura

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            password='admin123',  # Será hashado no app.py
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
    print("✅ Banco inicializado!")