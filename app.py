#!/usr/bin/env python3
import os
import sqlite3
import subprocess
import pickle
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    send_from_directory, flash
)
import requests
import xml.etree.ElementTree as ET

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'  
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['DEBUG'] = True  

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'database.db'))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT
        );
    ''')
    cur.execute('SELECT COUNT(*) as count FROM users WHERE username = ?', ('admin',))
    if cur.fetchone()['count'] == 0:
        cur.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                    ('admin', 'admin', 1))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                        (username, password))
            conn.commit()
            flash('Registration successful! Please log in.', 'info')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Choose another.', 'error')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        conn.close()
        if user and user['password'] == password:
            is_admin = int(request.form.get('is_admin', 0))
            session['username'] = username
            session['is_admin'] = is_admin or user['is_admin']
            flash('You are now logged in.', 'info')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/search', methods=['GET', 'POST'])
def search():
    results = None
    if request.method == 'POST':
        query = request.form.get('query', '')
        conn = get_db_connection()
        cur = conn.cursor()
        sql = "SELECT username, password, is_admin FROM users WHERE username = '%s'" % query
        try:
            cur.execute(sql)
            results = cur.fetchall()
        except Exception as e:
            results = [{'username': 'Error', 'password': str(e), 'is_admin': 0}]
        finally:
            conn.close()
    return render_template('search.html', results=results)

@app.route('/profile/<username>', methods=['GET', 'POST'])
def profile(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT message FROM messages WHERE username = ?', (username,))
    row = cur.fetchone()
    message = row['message'] if row else ''
    if request.method == 'POST' and session.get('username') == username:
        new_message = request.form.get('message', '')
        if row:
            cur.execute('UPDATE messages SET message = ? WHERE username = ?', (new_message, username))
        else:
            cur.execute('INSERT INTO messages (username, message) VALUES (?, ?)', (username, new_message))
        conn.commit()
        message = new_message
    conn.close()
    return render_template('profile.html', username=username, message=message)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    file_content = None
    filename = None
    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        if uploaded_file:
            filename = uploaded_file.filename
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(save_path)
            with open(save_path, 'rb') as f:
                try:
                    data = f.read()
                    try:
                        file_content = pickle.loads(data)
                    except Exception:
                        file_content = data.decode('utf-8', errors='ignore')
                except Exception as e:
                    file_content = f'Error reading file: {e}'
    return render_template('upload.html', filename=filename, file_content=file_content)

@app.route('/xml', methods=['GET', 'POST'])
def xml_parser():
    result = None
    if request.method == 'POST':
        xml_data = request.form.get('xml_data', '')
        try:
            root = ET.fromstring(xml_data)
            result = f"Parsed root tag: {root.tag}, text: {root.text}"
        except Exception as e:
            result = f'Error parsing XML: {e}'
    return render_template('xml.html', result=result)

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    output = None
    if request.method == 'POST':
        host = request.form.get('host', '')
        try:
            command = f'ping -c 1 {host}'
            output = subprocess.getoutput(command)
        except Exception as e:
            output = f'Error executing command: {e}'
    return render_template('ping.html', output=output)

@app.route('/fetch', methods=['GET', 'POST'])
def fetch():
    content = None
    if request.method == 'POST':
        url = request.form.get('url')
        try:
            response = requests.get(url, timeout=5)
            content = response.text[:200]
        except Exception as e:
            content = f'Error fetching URL: {e}'
    return render_template('fetch.html', content=content)

@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        flash('Access denied: administrators only.', 'error')
        return redirect(url_for('index'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username, password, is_admin FROM users')
    users = cur.fetchall()
    conn.close()
    return render_template('admin.html', users=users)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/info')
def info():
    data = {
        'cwd': os.getcwd(),
        'env': dict(list(os.environ.items())[:10])  
    }
    return render_template('info.html', data=data)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
