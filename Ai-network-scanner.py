#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import socket
import ipaddress
import psutil
import subprocess
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Optional

executor = ThreadPoolExecutor(max_workers=100)

# Common & critical ports
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 9090, 27017
]

# ---------------- INTERFACE SELECTION ----------------
def select_interface() -> str:
    try:
        ifaces = list(psutil.net_if_addrs().keys())
        if not ifaces:
            print("[!] No network interfaces found")
            sys.exit(1)

        print("\n" + "=" * 50)
        print("Available network interfaces:")
        print("=" * 50)
        for i, n in enumerate(ifaces, 1):
            addrs = psutil.net_if_addrs()[n]
            ipv4 = next((a.address for a in addrs if a.family == socket.AF_INET), "N/A")
            print(f"{i}. {n:<15} - {ipv4}")
        print("=" * 50)

        while True:
            choice = input("\n[?] Select interface (number): ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(ifaces):
                return ifaces[idx]
            print("[!] Invalid choice")

    except KeyboardInterrupt:
        sys.exit(0)

# ---------------- SERVICE MAP ----------------
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9090: "Mgmt",
    27017: "MongoDB"
}

def detect_service(port: int) -> str:
    return SERVICE_MAP.get(port, f"Unknown-{port}")

# ---------------- BANNER GRABBING ----------------
async def grab_banner(ip: str, port: int) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=2
        )

        if port in [21, 22, 25, 110, 143]:
            banner = await reader.read(512)
        elif port in [80, 8080]:
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            banner = await reader.read(512)
        else:
            banner = await reader.read(256)

        writer.close()
        await writer.wait_closed()

        return banner.decode(errors="ignore")[:100]

    except:
        return None

# ---------------- OS DETECTION (TTL) ----------------
async def detect_os_ttl(ip: str) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "1", ip,
            stdout=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode().lower()

        if "ttl=" in output:
            ttl = int(output.split("ttl=")[1].split()[0])
            if ttl <= 64:
                return "Linux / Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Network Device"
        return "Unknown"
    except:
        return "Unknown"

# ---------------- PORT CHECK ----------------
async def check_port(ip: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=0.5
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

async def smart_scan(ip: str) -> List[int]:
    tasks = [check_port(ip, p) for p in TOP_PORTS]
    results = await asyncio.gather(*tasks)
    return [p for p, r in zip(TOP_PORTS, results) if r]

# ---------------- HOST SCAN ----------------
async def scan_host(ip: str) -> Dict:
    print(f"[+] Scanning {ip}...", end="", flush=True)

    result = {
        "ip": ip,
        "status": "down",
        "os": "Unknown",
        "ports": []
    }

    os_type = await detect_os_ttl(ip)
    if os_type != "Unknown":
        result["status"] = "up"
        result["os"] = os_type

    open_ports = await smart_scan(ip)

    if open_ports:
        banner_tasks = [grab_banner(ip, p) for p in open_ports]
        banners = await asyncio.gather(*banner_tasks)

        for port, banner in zip(open_ports, banners):
            result["ports"].append({
                "port": port,
                "service": detect_service(port),
                "banner": banner
            })

        print(f" ✓ {len(open_ports)} open ports")
    else:
        print(" ✓ no open ports")

    return result

# ---------------- CIDR SCAN ----------------
async def cidr_scan(cidr: str) -> Dict[str, Dict]:
    net = ipaddress.ip_network(cidr, strict=False)
    tasks = [scan_host(str(ip)) for ip in net.hosts()]
    results = await asyncio.gather(*tasks)
    return {r["ip"]: r for r in results}

# ---------------- OLLAMA ANALYSIS ----------------
def analyze_with_ollama(data: Dict):
    total_hosts = len(data)
    up_hosts = sum(1 for h in data.values() if h["status"] == "up")
    total_ports = sum(len(h["ports"]) for h in data.values())

    services = {}
    for host in data.values():
        for p in host["ports"]:
            services[p["service"]] = services.get(p["service"], 0) + 1

    prompt = f"""
Analyse les résultats du scan réseau suivant sans aucune exploitation offensive.

Statistiques générales :
- Nombre total d’hôtes : {total_hosts}
- Hôtes actifs : {up_hosts}
- Nombre total de ports ouverts : {total_ports}

Services détectés :
{json.dumps(services, indent=2)}

Données complètes du scan :
{json.dumps(data, indent=2, ensure_ascii=False)}

Merci de fournir une analyse de sécurité complète incluant :
1. Un résumé global de l’état du réseau
2. Les hôtes et services exposés
3. Les risques et vulnérabilités potentielles (analyse théorique uniquement)
4. Des recommandations de sécurisation
5. Les priorités de remédiation

Utilise un langage clair, structuré et professionnel en français.
"""

    proc = subprocess.Popen(
        ["ollama", "run", "qwen2.5:7b"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )

    output, _ = proc.communicate(prompt)

    with open("ollama_security_analysis.txt", "w", encoding="utf-8") as f:
        f.write(output)

    print("[✓] Ollama security report generated")

# ---------------- MAIN ----------------
async def main():
    print("\nAI POWERED NETWORK SCANNER - LAB EDITION\n")

    iface = select_interface()
    print(f"[✓] Interface selected: {iface}")

    print("\n1) Single IP\n2) CIDR Scan")
    choice = input("Select mode: ").strip()

    if choice == "1":
        ip = input("IP address: ")
        result = await scan_host(ip)
        data = {ip: result}
    elif choice == "2":
        cidr = input("CIDR (ex: 192.168.1.0/24): ")
        data = await cidr_scan(cidr)
    else:
        print("Invalid option")
        return

    with open("scan_detailed.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    analyze_with_ollama(data)

    print("\nScan completed successfully")

if __name__ == "__main__":
    asyncio.run(main())

