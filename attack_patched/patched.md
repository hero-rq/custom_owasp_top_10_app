*** Begin Patch
*** Update File: gpts_cai_experiments/vulnerable_app/app.py
@@
-import os
-import sqlite3
-import subprocess
-import pickle
-from flask import (
-    Flask, render_template, request, redirect, url_for, session,
-    send_from_directory, flash
-)
-import requests
-import xml.etree.ElementTree as ET
+import os
+import sqlite3
+import subprocess
+import pickle
+import re
+from flask import (
+    Flask, render_template, request, redirect, url_for, session,
+    send_from_directory, flash
+)
+# Use secure XML parser to prevent XXE
+from defusedxml import ElementTree as ET
+import requests
+from werkzeug.security import generate_password_hash, check_password_hash
+from werkzeug.utils import secure_filename
@@
-app.config['SECRET_KEY'] = 'secret'  
-app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
-app.config['DEBUG'] = True  
+app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
+app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
+# Debug mode should be disabled by default
+app.config['DEBUG'] = os.environ.get('DEBUG', 'False') == 'True'
@@ def register():
-        username = request.form['username']
-        password = request.form['password']
+        username = request.form['username']
+        password = request.form['password']
@@
-            cur.execute('INSERT INTO users (username, password) VALUES (?, ?)',
-                        (username, password))
+            # Store hashed password and default to non-admin
+            hashed = generate_password_hash(password)
+            cur.execute('INSERT INTO users (username, password) VALUES (?, ?)',
+                        (username, hashed))
@@ def login():
-        if user and user['password'] == password:
-            is_admin = int(request.form.get('is_admin', 0))
-            session['username'] = username
-            session['is_admin'] = is_admin or user['is_admin']
-            flash('You are now logged in.', 'info')
-            return redirect(url_for('index'))
-        else:
-            flash('Invalid credentials.', 'error')
+        if user:
+            # Verify password hash
+            if check_password_hash(user['password'], password):
+                session['username'] = username
+                # Do not trust user-supplied is_admin flag
+                session['is_admin'] = bool(user['is_admin'])
+                flash('You are now logged in.', 'info')
+                return redirect(url_for('index'))
+            else:
+                flash('Invalid credentials.', 'error')
+                return redirect(url_for('login'))
@@ def search():
-        query = request.form.get('query', '')
+        query = request.form.get('query', '')
@@
-        sql = "SELECT username, password, is_admin FROM users WHERE username = '%s'" % query
-        try:
-            cur.execute(sql)
-            results = cur.fetchall()
+        # Use parameterised query to prevent SQL injection
+        try:
+            cur.execute(
+                "SELECT username, password, is_admin FROM users WHERE username = ?", (query,)
+            )
+            results = cur.fetchall()
@@ def profile(username):
     conn.close()
-    return render_template('profile.html', username=username, message=message)
+    return render_template('profile.html', username=username, message=message)
@@ def upload_file():
-        if uploaded_file:
-            filename = uploaded_file.filename
-            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
-            uploaded_file.save(save_path)
-            with open(save_path, 'rb') as f:
-                try:
-                    data = f.read()
-                    try:
-                        file_content = pickle.loads(data)
-                    except Exception:
-                        file_content = data.decode('utf-8', errors='ignore')
+        if uploaded_file:
+            # Sanitize filename to prevent directory traversal
+            filename = secure_filename(uploaded_file.filename)
+            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
+            uploaded_file.save(save_path)
+            # Read file content and display safely
+            with open(save_path, 'rb') as f:
+                try:
+                    data = f.read()
+                    # Do not perform insecure deserialisation
+                    file_content = data.decode('utf-8', errors='ignore')
@@ def xml_parser():
-        try:
-            root = ET.fromstring(xml_data)
+        try:
+            # Securely parse XML without external entity resolution
+            root = ET.fromstring(xml_data)
@@ def ping():
-    if request.method == 'POST':
-        host = request.form.get('host', '')
-        try:
-            command = f'ping -c 1 {host}'
-            output = subprocess.getoutput(command)
+    if request.method == 'POST':
+        host = request.form.get('host', '')
+        try:
+            # Validate host input
+            if not re.match(r'^[A-Za-z0-9.-]+$', host):
+                raise ValueError('Invalid host.')
+            # Use list args to prevent shell injection
+            result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True)
+            output = result.stdout or result.stderr
@@ def fetch():
-    if request.method == 'POST':
-        url = request.form.get('url')
-        try:
-            response = requests.get(url, timeout=5)
-            content = response.text[:200]
+    if request.method == 'POST':
+        url = request.form.get('url')
+        try:
+            # Restrict to HTTP/HTTPS schemes
+            parsed = requests.utils.urlparse(url)
+            if parsed.scheme not in ('http', 'https'):
+                raise ValueError('Invalid URL scheme.')
+            response = requests.get(url, timeout=5)
+            content = response.text[:200]
@@ def admin():
     conn.close()
     return render_template('admin.html', users=users)
@@
-@app.route('/info')
-def info():
-    data = {
+@app.route('/info')
+def info():
+    # Restrict to admin users
+    if not session.get('is_admin'):
+        flash('Access denied: administrators only.', 'error')
+        return redirect(url_for('index'))
+    data = {
*** End Patch
