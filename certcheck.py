# -*- coding: utf-8 -*-
import ssl
import socket
import subprocess
import xml
import xml.etree.ElementTree as ET
from xml.etree import ElementTree
import OpenSSL
from subprocess import Popen, PIPE
from datetime import datetime
from xml.dom import minidom
from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna

from socket import socket
from collections import namedtuple

def get_certificate(host, port=443, timeout=4):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)

def analyze_cert(url):
    certificate = get_certificate(url)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    expire_date = x509.get_notAfter()
    datetimeformat = '%Y-%m-%d %H:%M:%S'
    cert_status = datetime.strptime(expire_date.decode('ascii'), '%Y%m%d%H%M%SZ')
    return "Expiry date for "+str(url)+" is "+str(cert_status)

def run_command(command):
    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    return iter(p.stdout.readline, b'')


HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')


def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()
    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD)  # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE
    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()
    return cert.get_notAfter()


def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer


def check_it_out(hostname, port):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo)


def print_basic_info(hostinfo):
    # print(s)
    return hostinfo.cert.not_valid_after

if __name__ == '__main__':
    command = 'nmap -oX test.xml -p 443 128.205.40.0/23'.split()
    run_command(command)

    tree = ET.parse('test.xml')    # read in the xml to a variable called tree
    root = tree.getroot()    # assign the root element to a variable called root
    hosts = root.findall('host')    # find all elements named ‘host’

    for hostname in root.iter('hostname'):
        print(hostname.attrib['name'])
        try:
            check_it_out(hostname.attrib['name'],443)
        except Exception as ex:
            print(ex)

    remove_file = 'rm test.xml'.split()
    run_command(remove_file)
