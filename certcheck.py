import ssl
import socket
import OpenSSL
from datetime import datetime


def get_certificate(host, port=443, timeout=10):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)

certificate = get_certificate('google.com')
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
expire_date = x509.get_notAfter()
datetimeformat = '%Y-%m-%d %H:%M:%S'
cert_status = datetime.strptime(expire_date.decode('ascii'), '%Y%m%d%H%M%SZ')
print("Expiry date for google.com is "+str(cert_status))


