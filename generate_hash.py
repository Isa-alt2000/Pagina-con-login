from werkzeug.security import generate_password_hash

print("Hash para admin (admin123):", generate_password_hash('admin123'))
print("Hash para usuario (usuario123):", generate_password_hash('usuario123'))
 