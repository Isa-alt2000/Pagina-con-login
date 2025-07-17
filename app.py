from flask import Flask, render_template, request, redirect, session
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'clave_secreta_simple'

def get_db_connection():
    return psycopg2.connect(
        dbname="proyecto_db",
        user="isa_admin",
        password="1234",
        host="localhost",
        port="5432"
    )

# Decoradores de autenticación
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT id, username, password_hash, role FROM registered_users WHERE username = %s', (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            
            if user[3] == 'admin':
                return redirect('/admin/dashboard')
            else:
                return redirect('/user/view')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT id, nombre, correo FROM usuarios")
    usuarios = cur.fetchall()
    cur.close()
    conn.close()
    
    return render_template('admin/dashboard.html', usuarios=usuarios)

@app.route('/admin/agregar', methods=['POST'])
@admin_required
def agregar_usuario():
    nombre = request.form['nombre']
    correo = request.form['correo']
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO usuarios (nombre, correo) VALUES (%s, %s)", (nombre, correo))
    conn.commit()
    cur.close()
    conn.close()
    
    return redirect('/admin/dashboard')

@app.route('/admin/eliminar/<int:id>')
@admin_required
def eliminar_usuario(id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
    cur.close()
    conn.close()
    
    return redirect('/admin/dashboard')

@app.route('/user/view')
@login_required
def user_view():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, nombre, correo FROM usuarios")
    usuarios = cur.fetchall()
    cur.close()
    conn.close()
    
    return render_template('user/view.html', usuarios=usuarios)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)