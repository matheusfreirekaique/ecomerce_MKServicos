from app import app, db
from app import User  # Importa diretamente do app.py

with app.app_context():
    try:
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
        print("✅ Banco inicializado com sucesso!")
    except Exception as e:
        print(f"❌ Erro na inicialização: {str(e)}")
        raise