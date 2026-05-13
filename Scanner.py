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

def analyze_cookies(response):

    print("\n[COOKIES]")
    if not response.cookies:
        print("No se detectaron cookies")
        return

    for cookie in response.cookies:

        print(f"Cookie: {cookie.name}")
        print(f" Secure: {cookie.secure}")
        print(f" HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}")

def analyze_forms(html):

  print("\n[FORMULARIOS]")
  
  soup = BeautifulSoup(html, 'html.parser')
  forms = soup.find_all('form')
  
  if not forms:
    print("No se encontraron formularios")
    return
  
  for i, form in enumerate(forms, start=1):
  
    csrf_found = False
  
    for inp in form.find_all('input'):
      name = inp.get('name', '').lower()
    
      if 'csrf' in name or 'token' in name:
        csrf_found = True
  
    print(f"Formulario #{i}")
  
    if csrf_found:
      print(" [OK] Token CSRF detectado")
    else:
      print(" [ALERTA] No se detectó token CSRF")
      
def scan(url):
    print_banner()

    try:
        response = requests.get(url, timeout=10)

        print(f"\nURL: {url}")
        print(f"Estado HTTP: {response.status_code}")
        print(f"Servidor: {response.headers.get('Server', 'No detectado')}")

        check_headers(response.headers)
        analyze_cookies(response)
        analyze_forms(response.text)

        parsed = urlparse(url)

        if parsed.hostname:
            check_ssl(parsed.hostname)

        print("\nEscaneo finalizado")

    except requests.exceptions.RequestException as e:
        print("\n[ERROR] No se pudo conectar con el sitio")
        print(e)


if __name__ == '__main__':
    target = input("Introduce la URL objetivo: ")

    if not target.startswith("http"):
        target = "https://" + target

    scan(target)
