import os

# Chave secreta para sessões
SECRET_KEY = os.urandom(24).hex()

# Configurações de segurança
SESSION_PROTECTION = 'strong'