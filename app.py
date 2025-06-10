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
from flask_wtf import FlaskForm # type: ignore
from wtforms import StringField, SelectField, validators # type: ignore
from datetime import datetime

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
    created_by = db.Column(db.Integer, db.ForeignKey('public.users.id'))  # Corrigido para 'users.id'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    creator = db.relationship('User', backref='products', lazy=True)

# NOVAS CLASSES PARA PAGAMENTO
    
class PaymentForm(FlaskForm):
    """Formulário de pagamento"""
    payment_method = SelectField('Método de Pagamento', choices=[
        ('credit_card', 'Cartão de Crédito'),
        ('boleto', 'Boleto Bancário'),
        ('pix', 'PIX')
    ], validators=[validators.InputRequired()])
    
    # Campos para cartão de crédito
    card_number = StringField('Número do Cartão', validators=[
        validators.Optional(),
        validators.Length(min=16, max=16, message="Número inválido")
    ])
    card_name = StringField('Nome no Cartão', validators=[validators.Optional()])
    card_expiry = StringField('Validade (MM/AA)', validators=[
        validators.Optional(),
        validators.Regexp(r'^\d{2}/\d{2}$', message="Formato inválido")
    ])
    card_cvv = StringField('CVV', validators=[
        validators.Optional(),
        validators.Length(min=3, max=4, message="Código inválido")
    ])

class Order(db.Model):
    """Modelo para armazenar pedidos"""
    __tablename__ = 'orders'
    __table_args__ = {'schema': 'public'}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('public.users.id'))
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_id = db.Column(db.String(100))
    
    user = db.relationship('User', backref='orders', lazy=True)

    

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


with app.app_context():
    try:
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com',
                        password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
                        is_admin=True)
            db.session.add(admin)
            db.session.commit()
    except Exception as e:
        print(f"⚠️ Erro na inicialização: {str(e)}")

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

# ROTAS DE PAGAMENTO
@app.route('/checkout/<int:product_id>', methods=['GET', 'POST'])
@login_required
def checkout(product_id):
    """Rota para processar pagamentos com produto específico"""
    product = Product.query.get_or_404(product_id)  # Obtém o produto ou retorna 404
    form = PaymentForm()
    
    # Define o amount com base no produto
    amount = product.price
    
    if form.validate_on_submit():
        try:
            new_order = Order(
                user_id=current_user.id,
                product_id=product.id,  # Adicione este campo se quiser registrar qual produto foi comprado
                amount=amount,
                payment_method=form.payment_method.data,
                status='processing',
                transaction_id=f"TXN{secrets.token_hex(8).upper()}"
            )
            
            db.session.add(new_order)
            db.session.commit()
            
            if form.payment_method.data == 'credit_card':
                return redirect(url_for('payment_success', order_id=new_order.id))
            elif form.payment_method.data == 'boleto':
                boleto_url = url_for('generate_boleto', order_id=new_order.id, _external=True)
                return render_template('payment/boleto.html', 
                                    boleto_url=boleto_url,
                                    order=new_order,
                                    product=product)  # Adicione o produto aqui
            elif form.payment_method.data == 'pix':
                pix_code = f"00020126580014BR.GOV.BCB.PIX0136{secrets.token_hex(22)}5204000053039865405{amount:.2f}5802BR5925EMPRESA EXEMPLO6008BRASILIA62070503***6304"
                return render_template('payment/pix.html',
                                    pix_code=pix_code,
                                    order=new_order,
                                    product=product)  # Adicione o produto aqui
                
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao processar pagamento: {str(e)}', 'danger')
            app.logger.error(f'Payment error: {str(e)}')
    
    return render_template('payment/checkout.html', 
                         form=form,
                         amount=amount,
                         product=product)  
    
@app.route('/payment/success/<int:order_id>')
@login_required
def payment_success(order_id):
    """Rota de confirmação de pagamento"""
    order = Order.query.get_or_404(order_id)
    
    # Verificar se o pedido pertence ao usuário atual
    if order.user_id != current_user.id:
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('index'))
    
    # Atualizar status (em um sistema real, isso viria do gateway)
    order.status = 'completed'
    db.session.commit()
    
    # Enviar e-mail de confirmação (simulado)
    try:
        msg = Message(
            '✅ Pagamento Confirmado',
            recipients=[current_user.email],
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        msg.body = f'''Olá {current_user.username},

Seu pagamento no valor de R$ {order.amount:.2f} foi confirmado!
Método: {order.payment_method.replace('_', ' ').title()}
ID da Transação: {order.transaction_id}

Agradecemos pela sua compra!
'''
        mail.send(msg)
    except Exception as e:
        app.logger.error(f'Error sending confirmation email: {str(e)}')
    
    return render_template('payment/success.html', order=order)

@app.route('/boleto/<int:order_id>')
@login_required
def generate_boleto(order_id):
    """Rota para gerar boleto fictício (em produção, integrar com API real)"""
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.id:
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('index'))
    
    # Dados fictícios do boleto
    boleto_data = {
        'codigo_barras': f'34191.11111 11111.111111 11111.111111 1 999900000{order.amount:.2f}',
        'linha_digitavel': f'34191.11111 11111.111111 11111.111111 1 999900000{order.amount:.2f}',
        'vencimento': (datetime.utcnow() + timedelta(days=3)).strftime('%d/%m/%Y'),
        'valor': f'R$ {order.amount:.2f}',
        'beneficiario': 'Empresa Exemplo Ltda',
        'documento': order.transaction_id
    }
    
    return render_template('payment/boleto_pdf.html', boleto=boleto_data)

# ... (mantenha quaisquer outras rotas que você já tinha)

def init_db():
    with app.app_context():
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
        print("✅ Banco inicializado!")

if os.environ.get('INIT_DB') == '1':
    init_db()


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