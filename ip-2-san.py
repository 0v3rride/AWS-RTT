import argparse
import ssl
import socket
import cryptography
import cryptography.hazmat.backends
import cryptography.x509
import prettytable

parser = argparse.ArgumentParser(description = "Reverse DNS lookup on EC2/AZ/GCP compute public instances.")
parser.add_argument("-i", "--ips", action="append", help="List containing IP addresses of EC2, AZ or GCP compute instances that you want to tie a domain to.", required=True)
parser.add_argument("-v", "--verbose", action="store_true", help="Give verbose output including invalid resources.", required=False)

args = parser.parse_args()


def get_commmon_name(certificate):
    for attr in certificate.subject:
        if attr.oid._name == "commonName":
            return attr.value
        

def get_subject_alternative_names(ip):
    sans = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False

    # ctx.verify_mode = ssl.CERT_NONE
    sock = socket.socket(socket.AF_INET)
    sock.settimeout(10)

    with ctx.wrap_socket(sock, server_hostname=ip) as s:
        s.connect((ip, 443))
        
        for domain in s.getpeercert()["subjectAltName"]:
            sans.append(domain[1])

    return sans


if len(args.ips) > 0:
    for ip in args.ips:
        table = prettytable.PrettyTable()
        table.title = f"{ip}"
        table.field_names = ["Domains"]
        try:
            pem = ssl.get_server_certificate((ip, 443), timeout=10).encode('utf-8')
            certificate = cryptography.x509.load_pem_x509_certificate(pem, cryptography.hazmat.backends.default_backend())
            
            sans = get_subject_alternative_names(ip)
            cn = get_commmon_name(certificate)

            if cn not in sans:
                sans.append(f"--> {cn}")
            else:
                sans.remove(cn)
                sans.append(f"--> {cn}")

            for fqdn in sans:
                table.add_row([fqdn])
            
            print(table)
        except TimeoutError as te:
            print(f"Timeout: {ip}\n")
        except Exception as e:
            print(f"Error {e}: {ip}\n")


