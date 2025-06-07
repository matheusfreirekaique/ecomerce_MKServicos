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


app = Flask(__name__)
app.config.from_pyfile('config.py')

# Configurações do banco de dados (CORRIGIDO)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']  # Sem fallback!
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {
        'sslmode': 'require'  # Adiciona SSL obrigatório
    }
}
# Configurações de segurança (CORRETO)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configurações de email (CORRETO)
app.config.update(
    MAIL_SERVER='smtp.example.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@example.com')
)

# Inicialização das extensões (CORRETO)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

# Configuração do Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelos do banco de dados (mantidos como estavam)
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    __table_args__ = {'schema': 'public'}
    
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
    __table_args__ = {'schema': 'public'}
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Atualizado
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    creator = db.relationship('User', backref='products', lazy=True)
    
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorador para verificar admin (mantido como estava)
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Acesso restrito a administradores', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.cli.command("init-db")
@with_appcontext
def init_db_command():
    """Inicializa o banco de dados"""
    try:
        db.drop_all()
        db.create_all()
        
        # Cria admin padrão se não existir
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
        
        print("✅ Banco de dados inicializado com sucesso!")
    except Exception as e:
        print(f"❌ Erro ao inicializar banco: {str(e)}")
        raise


# ==============================================
# NOVAS FUNÇÕES PARA RECUPERAÇÃO DE SENHA
# ==============================================

def send_reset_email(user):
    try:
        # Gera token seguro (válido por 1 hora)
        token = secrets.token_urlsafe(32)
        user.reset_token = token
        user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        
        # Cria link absoluto (funciona em qualquer ambiente)
        reset_url = url_for('reset_password', token=token, _external=True)
        
        # Configura o e-mail
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
        # Envia o e-mail
        mail.send(msg)
        return True
    except Exception as e:
        print(f"ERRO NO ENVIO: {str(e)}")  # Log detalhado
        db.session.rollback()
        return False

# ==============================================
# NOVAS ROTAS PARA RECUPERAÇÃO DE SENHA
# ==============================================

@app.route('/forget-password', methods=['GET', 'POST'])
def forget_password():
    """Rota para solicitar recuperação de senha"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            try:
                send_reset_email(user)
                flash('Um email com instruções para resetar sua senha foi enviado.', 'info')
                return redirect(url_for('login'))
            except Exception as e:
                flash('Ocorreu um erro ao enviar o email. Tente novamente mais tarde.', 'danger')
                app.logger.error(f'Erro ao enviar email: {str(e)}')
        else:
            flash('Nenhuma conta encontrada com este email.', 'danger')
    
    return render_template('forget_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Rota para redefinir a senha usando o token"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expires < datetime.utcnow():
        flash('O token é inválido ou expirou. Solicite um novo.', 'danger')
        return redirect(url_for('forget_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('As senhas não coincidem.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()
        
        flash('Sua senha foi atualizada com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# ==============================================
# ROTAS EXISTENTES (MANTIDAS EXATAMENTE COMO ESTAVAM)
# ==============================================

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login realizado com sucesso!', 'success')
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Usuário ou senha incorretos', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('As senhas não coincidem', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            is_admin=False,
            can_view_products=True
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Conta criada com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Erro ao criar conta. Usuário ou email já existem.', 'danger')
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você foi deslogado', 'info')
    return redirect(url_for('index'))

# Rotas do usuário comum
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if not current_user.can_view_products:
        flash('Você não tem permissão para visualizar produtos', 'danger')
        return redirect(url_for('index'))
    
    products = Product.query.filter_by(is_active=True).all()
    return render_template('user/dashboard.html', products=products)

# Rotas do admin
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    products = Product.query.all()
    return render_template('admin/dashboard.html', users=users, products=products)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

#rota para tornar admin 
# ------ NOVAS ROTAS PARA GERENCIAMENTO DE USUÁRIOS ------ #
@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def make_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    # Impede que o admin atual modifique seu próprio status
    if user.id == current_user.id:
        flash('Você não pode alterar seu próprio status de admin!', 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        user.is_admin = not user.is_admin  # Alterna entre True/False
        db.session.commit()
        action = "promovido a" if user.is_admin else "rebaixado de"
        flash(f'{user.username} {action} administrador!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao atualizar status: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/toggle_view_products/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_view_products(user_id):
    user = User.query.get_or_404(user_id)
    
    try:
        user.can_view_products = not user.can_view_products  # Alterna entre True/False
        db.session.commit()
        action = "habilitado para" if user.can_view_products else "desabilitado de"
        flash(f'{user.username} {action} visualizar produtos!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao atualizar permissão: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))
# ------ FIM DAS NOVAS ROTAS ------ #

@app.route('/admin/products', methods=['GET', 'POST'])  # Adicione 'POST' aqui
@login_required
@admin_required
def admin_products():
    if request.method == 'POST':
        # Lógica para salvar o produto
        try:
            name = request.form.get('name')
            description = request.form.get('description')
            price = float(request.form.get('price'))
            
            new_product = Product(
                name=name,
                description=description,
                price=price,
                created_by=current_user.id,
                is_active=True
            )
            
            db.session.add(new_product)
            db.session.commit()
            flash('Produto salvo com sucesso!', 'success')
            return redirect(url_for('admin_products'))  # Recarrega a página após salvar
            
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao salvar produto: {str(e)}', 'danger')
    
    # Lógica original (GET) para listar produtos
    products = Product.query.all()
    return render_template('admin/products.html', products=products)

# Products/delete
@app.route('/admin/products/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    
    try:
        db.session.delete(product)
        db.session.commit()
        flash('Produto excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir produto: {str(e)}', 'danger')
    
    return redirect(url_for('admin_products'))
# PRODUCTS/EDIT
@app.route('/admin/products/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_product(id):
    product = Product.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            product.name = request.form.get('name')
            product.description = request.form.get('description')
            product.price = float(request.form.get('price'))
            db.session.commit()
            flash('Produto atualizado com sucesso!', 'success')
            return redirect(url_for('admin_products'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar produto: {str(e)}', 'danger')
    
    return render_template('admin/edit_product.html', product=product)


# ... (mantenha quaisquer outras rotas que você já tinha)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Criar admin padrão se não existir
        if not User.query.filter_by(username='admin').first():
            hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin = User(
                username='admin',
                email='admin@example.com',
                password=hashed_password,
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)