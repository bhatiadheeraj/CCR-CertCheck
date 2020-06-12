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

command = 'nmap -oX test.xml -p 443 128.205.40.0/23'.split()
run_command(command)

tree = ET.parse('test.xml')    # read in the xml to a variable called tree
root = tree.getroot()    # assign the root element to a variable called root
hosts = root.findall('host')    # find all elements named ‘host’

for hostname in root.iter('hostname'):
    print(hostname.attrib['name'])

remove_file = 'rm test.xml'.split()
run_command(remove_file)

