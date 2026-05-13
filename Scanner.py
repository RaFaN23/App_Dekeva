import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
import socket

SECURITY_HEADERS = [
'Content-Security-Policy',
'Strict-Transport-Security',
'X-Content-Type-Options',
'X-Frame-Options',
'Referrer-Policy'
]

def print_banner():
  print("=" * 60)
  print(" WEB SECURITY AUDITOR ")
  print("=" * 60)
def check_ssl(hostname):
  try:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=5) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
    cert = ssock.getpeercert()
    print("\n[SSL] Certificado válido")
    print("[SSL] Emisor:", cert.get('issuer'))
  except Exception as e:
    print("\n[SSL] Error SSL:", e)


def check_headers(headers):
    print("\n[HEADERS DE SEGURIDAD]")

    for header in SECURITY_HEADERS:
        if header in headers:
            print(f"[OK] {header}")
        else:
            print(f"[FALTA] {header}")
