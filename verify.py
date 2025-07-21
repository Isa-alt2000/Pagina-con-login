# Prueba manual
from werkzeug.security import check_password_hash

stored_hash = "scrypt:32768:8:1$oynSHz2gY1bRe8Vp$1b1514779917c29c9f1b139e8ab507312c0915f126018acba75afe26b5e23264c2dbc78f3c20823bc2e9cdac9dab1fe53d2dbdc8353a66e2d85f07b621c92f1d"
password = "admin123"

print(check_password_hash(stored_hash, password))  # Debería ser True
