Vulnerability Remediation Report
===============================

1. Insecure Configuration:
   - Hard-coded SECRET_KEY replaced with env var or random.
   - Debug mode disabled by default.

2. Plaintext Password Storage:
   - Passwords now hashed (Werkzeug generate_password_hash) on register.

3. Broken Access Control (Login):
   - is_admin flag no longer trusted from user input; now from database only.

4. SQL Injection (/search endpoint):
   - Changed to parameterised queries (sqlite3 '?').

5. Cross-Site Scripting (/profile endpoint):
   - Automatically escaped by Jinja; removed unsafe handling.

6. Insecure File Upload (/upload endpoint):
   - Filenames sanitized (secure_filename).
   - Removed insecure pickle deserialisation.

7. XML External Entity (XXE) (/xml endpoint):
   - Switched to defusedxml.ElementTree to prevent XXE.

8. Command Injection (/ping endpoint):
   - Validated hostname regex.
   - Used subprocess.run with list args to avoid shell.

9. Server-Side Request Forgery (/fetch endpoint):
   - Restricted to http/https schemes.

10. Admin Dashboard Broken Access (/info endpoint):
    - Added access control check for admin user.

Patch Location:
   - applied_patches/patch_20250806T124944.patch

