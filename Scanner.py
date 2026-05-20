from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
import socket
import psycopg2
import redis
import json
from playwright.sync_api import sync_playwright

app = Flask(__name__)
CORS(app)


cache = redis.Redis(host='localhost', port=6379, db=0)


def get_conn():
    return psycopg2.connect(
        dbname="scanner",
        user="postgres",
        password="kantero@09",
        host="localhost",
        port="5432"
    )


SECURITY_HEADERS = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Referrer-Policy'
]


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

HEADER_VULNS = {
    'Content-Security-Policy': 'Posible XSS y carga de scripts maliciosos',
    'Strict-Transport-Security': 'Posible downgrade a HTTP inseguro',
    'X-Content-Type-Options': 'Posible MIME sniffing',
    'X-Frame-Options': 'Posible Clickjacking',
    'Referrer-Policy': 'Filtración de información sensible',
    'Permissions-Policy': 'Abuso de permisos del navegador'
}


def check_headers(headers):
    results = []

    for h in SECURITY_HEADERS:
        exists = h in headers

        if exists:
            results.append({
                "header": h,
                "status": "OK",
                "message": "Sin vulnerabilidades detectadas"
            })
        else:
            results.append({
                "header": h,
                "status": "FALTA",
                "message": HEADER_VULNS.get(h, "Riesgo desconocido")
            })

    return results


def analyze_cookies(response):
    results = []

    for cookie in response.cookies:
        results.append({
            "name": cookie.name,
            "secure": cookie.secure,
            "httpOnly": cookie._rest.get('HttpOnly', False)
        })

    return results


def analyze_forms(html):
    soup = BeautifulSoup(html, 'html.parser')

    forms = soup.find_all('form')

    results = []

    for i, form in enumerate(forms, start=1):

        inputs = form.find_all('input')

        csrf_found = any(
            'csrf' in (inp.get('name') or '').lower() or
            'token' in (inp.get('name') or '').lower()
            for inp in inputs
        )

        results.append({
            "form": i,
            "inputs": len(inputs),
            "csrf": csrf_found
        })

    return results


def save_scan(data):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scans (url, status_code, server) VALUES (%s, %s, %s)",
            (data["url"], data["status_code"], data["server"])
        )
        conn.commit()
        cur.close()
        conn.close()
        print(">>> GUARDADO EN POSTGRESQL <<<")
    except Exception as e:
        print("Error guardando en PostgreSQL:", e)


def scan(url):

    cached = cache.get(url)
    if cached:
        print(">>> RESPUESTA DESDE REDIS <<<")
        return json.loads(cached.decode())

    print(">>> ESCANEANDO URL (BROWSER MODE) <<<")

    try:
        r = requests.get(url, timeout=10)
        status = r.status_code
        server = r.headers.get("Server", "Desconocido")
        headers = check_headers(r.headers)
    except:
        status = None
        server = None
        headers = None

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, timeout=10000)
        html = page.content()
        cookies = page.context.cookies()
        browser.close()

    parsed = urlparse(url)
    ssl_data = check_ssl(parsed.hostname)

    data = {
        "url": url,
        "status_code": status,
        "server": server,
        "headers": headers,
        "cookies": cookies,
        "forms": analyze_forms(html),
        "ssl": ssl_data
    }

    cache.setex(url, 60, json.dumps(data))
    save_scan(data)

    return data



@app.route('/scan')
def web_scan():
    url = request.args.get('url')

    if not url:
        return jsonify({"error": "No URL provided"})

    if not url.startswith("http"):
        url = "https://" + url

    result = scan(url)
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)
