from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
import socket
import psycopg2

app = Flask(__name__)
CORS(app)

# =========================
# POSTGRESQL CONNECTION
# =========================

def get_conn():
    return psycopg2.connect(
        dbname="scanner",
        user="postgres",
        password="TU_CONTRASEÑA",
        host="localhost",
        port="5432"
    )

# =========================
# SECURITY HEADERS
# =========================

SECURITY_HEADERS = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Referrer-Policy'
]

# =========================
# SSL CHECK
# =========================

def check_ssl(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "issuer": str(cert.get('issuer'))
                }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e)
        }

# =========================
# HEADERS ANALYSIS
# =========================

def check_headers(headers):
    results = []
    for header in SECURITY_HEADERS:
        results.append({
            "header": header,
            "status": "OK" if header in headers else "FALTA"
        })
    return results

# =========================
# COOKIES ANALYSIS
# =========================

def analyze_cookies(response):
    results = []
    if not response.cookies:
        return results

    for cookie in response.cookies:
        results.append({
            "name": cookie.name,
            "secure": cookie.secure,
            "httpOnly": cookie.has_nonstandard_attr('HttpOnly')
        })
    return results

# =========================
# FORMS ANALYSIS
# =========================

def analyze_forms(html):
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    results = []

    for i, form in enumerate(forms, start=1):
        csrf_found = False
        for inp in form.find_all('input'):
            name = inp.get('name', '').lower()
            if 'csrf' in name or 'token' in name:
                csrf_found = True

        results.append({
            "form": i,
            "csrf": csrf_found
        })

    return results

# =========================
# SAVE TO DATABASE
# =========================

def save_scan(url, status_code, server):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scans (url, status_code, server) VALUES (%s, %s, %s)",
            (url, status_code, server)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("Error guardando en PostgreSQL:", e)

# =========================
# MAIN SCAN
# =========================

def scan(url):
    try:
        print(">>> GUARDANDO EN POSTGRESQL <<<")

        response = requests.get(url, timeout=10)

        parsed = urlparse(url)
        ssl_data = check_ssl(parsed.hostname) if parsed.hostname else None

        # Guardar en PostgreSQL
        save_scan(url, response.status_code, response.headers.get('Server', 'No detectado'))

        data = {
            "url": url,
            "status_code": response.status_code,
            "server": response.headers.get('Server', 'No detectado'),
            "headers": check_headers(response.headers),
            "cookies": analyze_cookies(response),
            "forms": analyze_forms(response.text),
            "ssl": ssl_data
        }

        return data

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

# =========================
# API ROUTE
# =========================

@app.route('/scan')
def web_scan():
    url = request.args.get('url')

    if not url:
        return jsonify({"error": "No URL provided"})

    if not url.startswith("http"):
        url = "https://" + url

    result = scan(url)
    return jsonify(result)

# =========================
# RUN SERVER
# =========================

if __name__ == '__main__':
    app.run(debug=True)
