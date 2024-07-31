import argparse
import ssl
import socket
import cryptography
import cryptography.hazmat.backends
import cryptography.x509
import prettytable
import re
import colorama
import dns.resolver

parser = argparse.ArgumentParser(description = "Reverse DNS lookup on EC2/AZ/GCP compute/vm public instances.")
parser.add_argument("-i", "--ips", action="append", help="List containing IP addresses or urls (http://ec2-X-X-X-X.us-east-2.compute.amazonaws.com) of EC2, AZ or GCP compute instances that you want to tie a domain to.", required=True)
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
    # ctx.ssl_version = ssl.PROTOCOL_TLSv1_2
    ctx.verify_mode = ssl.CERT_OPTIONAL
    sock = socket.socket(socket.AF_INET)
    sock.settimeout(10)

    with ctx.wrap_socket(sock, server_hostname=ip) as s:
        s.connect((ip, 443))
        
        for domain in s.getpeercert()["subjectAltName"]:
            sans.append(domain[1])

    return sans


def ec2_url_to_ip(ec2url):
    ip = ec2url.split(".")[0]
    ip = ".".join(ip.split("-")[1:])

    return ip


def gcp_compute_to_ip(gcpurl):
    ip = gcpurl.split(".")[0:4]
    ip.reverse()

    return ".".join(ip)


def get_ptr_record(ip):
    ptr = None

    try:
        ptr = socket.gethostbyaddr(ip)
    except Exception as e: 
        pass

    return ptr


def get_a_record(hostname):
    # dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    # dns.resolver.default_resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']

    ip = None

    try:
        a = resolver.resolve(hostname, "A")

        for val in a:
            ip = val.to_text()
    except Exception as e:
        pass

    return ip


def get_cname_record(hostname):
    # dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    # dns.resolver.default_resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']

    cname = None

    try:
        cname = resolver.resolve(hostname, "CNAME")

        for val in cname:
            cname = val.to_text()
    except Exception as e:
        pass

    return cname


if len(args.ips) > 0:
    for host in args.ips:
        table = prettytable.PrettyTable()
        table.title = f"{host}"
        table.header = False
        
        try:
            # Certificate Transparency
            pem = ssl.get_server_certificate((host, 443), timeout=10).encode('utf-8')
            certificate = cryptography.x509.load_pem_x509_certificate(pem, cryptography.hazmat.backends.default_backend())

            sans = get_subject_alternative_names(host)
            sans.append(host)
            
            cn = get_commmon_name(certificate)

            # Get a, ptr and cname information
            for san in sans:
                ptr = None
                a = None
                cname = None

                a = get_a_record(san)
                cname = get_cname_record(san)
                ptr = get_ptr_record(san)


                if ptr:
                    if "googleusercontent.com" in ptr[0]:
                        if "googleusercontent.com" not in " ".join(sans):
                            sans.append(ptr[0])
                    if "amazonaws.com" in ptr[0]:
                        if "amazonaws.com" not in " ".join(sans):
                            sans.append(ptr[0])
                
                if a and a not in sans:
                    sans.append(a)
                
                if cname and cname not in sans:
                    sans.append(cname)


            # Highlight CN (main fqdn) in green
            if cn not in sans:
                sans.append(f"{colorama.Style.RESET_ALL}>>> {colorama.Back.GREEN}{colorama.Fore.WHITE}{cn}{colorama.Style.RESET_ALL} <<<")
            elif host not in sans:
                sans.append(host)
            else:
                sans.remove(cn)
                sans.append(f"{colorama.Style.RESET_ALL}>>> {colorama.Back.GREEN}{colorama.Fore.WHITE}{cn}{colorama.Style.RESET_ALL} <<<")


            # Build table
            count = 0 

            for fqdn in sans:
                color = colorama.Fore.WHITE

                if count % 2 == 0:
                    color = colorama.Fore.CYAN

                table.add_row([f"{color}{fqdn}{colorama.Style.RESET_ALL}"])
                count += 1
            
            print(f"{table}\n")
        except TimeoutError as te:
            print(f"Timeout: {host}\n")
        except Exception as e:
            print(f"Error {e}: {host}\n")
