#!/usr/bin/python3

"""
AthenaExplorer - Domain and IP Analysis Tool
============================================

A powerful tool for domain and IP information gathering, designed to assist security professionals
and network administrators in understanding the infrastructure behind a domain or IP address.

Features:
- WHOIS lookup for domain authority and registration details
- IP address resolution and geolocation data
- RDAP queries for NetBlock and ASN information
- Provider and network range identification

Version: 1.0
Release Date: March 2025
Author: xM4skByt3z
GitHub: https://github.com/xM4skByt3z
License: CUSTOM
"""



import socket
import sys
import requests

# Colors
default_color = "\033[0m"
yellow = "\033[1;33m"
light_green = "\033[1;32m"
cyan = "\033[0;36m"
dark_purple = "\033[38;2;128;0;128m"
light_purple = "\033[38;2;186;85;211m"
white = "\033[1;37m"
gray = "\033[38;2;169;169;169m"
light_red = "\033[38;2;255;99;71m"
dark_red = "\033[38;2;139;0;0m"


def ascii_art1():
    print(f"{white}╔═╗┌┬┐┬ ┬┌─┐┌┐┌┌─┐╔═╗─┐ ┬┌─┐┬  ┌─┐┬─┐┌─┐┬─┐")
    print(f"{gray}╠═╣ │ ├─┤├┤ │││├─┤║╣ ┌┴┬┘├─┘│  │ │├┬┘├┤ ├┬┘")
    print(f"{yellow}╩ ╩ ┴ ┴ ┴└─┘┘└┘┴ ┴╚═╝┴ └─┴  ┴─┘└─┘┴└─└─┘┴└─{default_color}")
    print(f"{white}                         by xM4skByt3z v1.0\n")


def ascii_art2():
    print(f"{white}╔═╗┌┬┐┬ ┬┌─┐┌┐┌┌─┐╔═╗─┐ ┬┌─┐┬  ┌─┐┬─┐┌─┐┬─┐")
    print(f"{gray}╠═╣ │ ├─┤├┤ │││├─┤║╣ ┌┴┬┘├─┘│  │ │├┬┘├┤ ├┬┘")
    print(f"{light_green}╩ ╩ ┴ ┴ ┴└─┘┘└┘┴ ┴╚═╝┴ └─┴  ┴─┘└─┘┴└─└─┘┴└─{default_color}")
    print(f"{white}                         by xM4skByt3z v1.0\n\n")


def whois():
    global refer
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.iana.org", 43))
    s.send((sys.argv[1] + "\r\n").encode('latin-1'))
    response = s.recv(2024).decode('latin-1')
    
    for line in response.split("\n"):
        if line.lower().startswith("refer:"):
            refer = line.split(":")[1].strip()
            print("\nAuthority: ", refer)
            break

    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.connect((refer, 43))
    s1.send((sys.argv[1] + "\r\n").encode('latin-1'))
    resp = s1.recv(4024).decode('latin-1')

    filtered_resp = "\n".join(line for line in resp.split("\n") if not line.startswith("%"))
    print(filtered_resp)
    print(f"{light_green}------------------------------------------{default_color}")


def ip_func():
    global ip
    ip = socket.gethostbyname(sys.argv[1])


def rdap():
    endpoints = [
        f"https://rdap.registro.br/ip/{ip}",
        f"https://rdap.db.ripe.net/ip/{ip}",
        f"https://rdap.arin.net/ip/{ip}",
        f"https://rdap.lacnic.net/ip/{ip}",
        f"https://rdap.apnic.net/ip/{ip}",
        f"https://rdap.afrinic.net/ip/{ip}"
    ]

    for endpoint in endpoints:
        response = requests.get(endpoint)
        
        if response.status_code == 200:
            data = response.json()
            print(f"{cyan}Querying {default_color}{light_green}NetBlock/ASN{default_color}{cyan} for domain:{default_color}{light_green} {sys.argv[1]}{default_color}{cyan} - [RDAP]{default_color}\n")

            if "handle" in data:
                handle = data["handle"]
                if " - " in handle:
                    print(f"{yellow}[+] Netblock - Range:{default_color} {handle}")
                elif "/" in handle:
                    print(f"{yellow}[+] ASN Prefix:{default_color} {handle}")

            if "asn" in data or "nicbr_autnum" in data:
                asn = data.get("asn", data.get("nicbr_autnum"))
                print(f"{yellow}[+] ASN:{default_color} AS{asn}")

                asn_url = f"https://rdap.registro.br/autnum/{asn}"
                asn_response = requests.get(asn_url)

                if asn_response.status_code == 200:
                    asn_data = asn_response.json()
                    if "entities" in asn_data:
                        for entity in asn_data["entities"]:
                            if "vcardArray" in entity:
                                for vcard in entity["vcardArray"]:
                                    if isinstance(vcard, list):
                                        for item in vcard:
                                            if isinstance(item, list) and item[0] == "fn":
                                                print(f"{yellow}[+] ASN Name:{default_color} {item[3]}")
                                                break

            if "entities" in data:
                for entity in data["entities"]:
                    if "roles" in entity and "registrant" in entity["roles"]:
                        if "vcardArray" in entity:
                            for vcard in entity["vcardArray"]:
                                if isinstance(vcard, list):
                                    provider_name = None
                                    provider_location = None

                                    for item in vcard:
                                        if isinstance(item, list) and item[0] == "fn":
                                            provider_name = item[3]
                                        if isinstance(item, list) and item[0] == "adr":
                                            if isinstance(item[1], dict) and "label" in item[1]:
                                                provider_location = item[1]["label"].replace("\n", ", ")

                                    if provider_location:
                                        print(f"{yellow}[+] Provider Location:{default_color} {provider_location}")
                                    if provider_name:
                                        print(f"{yellow}[+] Provider Name:{default_color} {provider_name}")
                                    elif provider_name:
                                        print(f"{yellow}[+] Provider Location:{default_color} Not available")
            return

    print(f"{yellow}Error querying RDAP: No available endpoint{default_color}")


if len(sys.argv) != 2:
    ascii_art1()
    print(f"{yellow}Usage: python3 AthenaExplorer.py <domain>{default_color}")
    sys.exit(1)

else:
    ascii_art2()
    print(f"{light_green}--------- [{sys.argv[1]}{light_green}] ---------{default_color}")
    print(f"{cyan}WHOIS query for domain authority:{default_color}")
    whois()
    ip_func()
    rdap()
