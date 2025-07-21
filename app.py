from flask import Flask, make_response, render_template, request, redirect, session, url_for, flash
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import csv
from io import StringIO
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)
app.secret_key = 'clave_secreta_simple'
app.debug = True

def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT")
        )
        return conn
    except psycopg2.Error as e:
        print(f"Error al conectar a la base de datos: {e}")
        return None

#Auth si no se tiene rol
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
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT id, username, password_hash, role FROM registered_users WHERE username = %s',
                    (username,)
                )
                user = cur.fetchone()
                
                if user and check_password_hash(user[2], password):
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    session['role'] = user[3]
                    
                    if user[3] == 'admin':
                        return redirect('/admin/dashboard')
                    else:
                        return redirect('/user/view')
                else:
                    flash('Credenciales inválidas')
        finally:
            conn.close()
    
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nombre, correo FROM usuarios")
            usuarios = [{'id': row[0], 'nombre': row[1], 'correo': row[2]} for row in cur.fetchall()]
            
            return render_template('admin/dashboard.html', usuarios=usuarios)
    except Exception as e:
        print(f"Error en dashboard: {e}") 
        flash('Error al cargar el panel de administración', 'error')
        return redirect(url_for('login'))
    finally:
        conn.close()

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
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nombre, correo FROM usuarios")

            columns = [desc[0] for desc in cur.description]
            usuarios = [dict(zip(columns, row)) for row in cur.fetchall()]
            
            return render_template('user/view.html', usuarios=usuarios)
    except Exception as e:
        print(f"Error en user_view: {e}")
        flash('Error al cargar los usuarios', 'error')
        return redirect(url_for('index'))
    finally:
        conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/export/csv')
@admin_required
def export_to_csv():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nombre, correo FROM usuarios")
            usuarios = cur.fetchall()
            
            csv_buffer = StringIO()
            csv_writer = csv.writer(csv_buffer)
            
            csv_writer.writerow(['ID', 'Nombre', 'Correo'])
            csv_writer.writerows(usuarios)
            
            response = make_response(csv_buffer.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = 'attachment; filename=usuarios.csv'
            
            return response
            
    except Exception as e:
        print(f"Error al exportar CSV: {e}")
        flash('Error al generar el archivo CSV', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        conn.close()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
