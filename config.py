import os

# Chave secreta para sessões
SECRET_KEY = os.urandom(24)

# Configurações de segurança
SESSION_PROTECTION = 'strong'