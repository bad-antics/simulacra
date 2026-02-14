"""Simulacra Network Analyzer — Ontological classification of network entities.

Examines network connections and services through the lens of Baudrillard's
simulacra theory — distinguishing authentic services from simulations,
honeypots, and phantom endpoints.
"""

import socket
import json
from datetime import datetime


class NetworkSimulacra:
    """Classify network entities by simulacra order."""

    # Well-known port/service mappings (Order 1 — authentic services)
    AUTHENTIC_SERVICES = {
        22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        993: "IMAPS", 995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    }

    # Honeypot signatures (Order 3 — masks absence of real service)
    HONEYPOT_INDICATORS = {
        "cowrie": ["SSH-2.0-OpenSSH_6.0p1", "SSH-2.0-OpenSSH_5.9p1"],
        "kippo": ["SSH-2.0-OpenSSH_5.1p1"],
        "dionaea": ["220 DionaeaFTP", "Microsoft-IIS/6.0"],
        "conpot": ["Siemens", "SCADA"],
    }

    # Deceptive port combinations suggesting traps
    TRAP_PATTERNS = [
        {21, 22, 23, 25, 80, 443, 3306, 8080},  # Too many services = honeypot
    ]

    def classify_endpoint(self, host, port, banner=""):
        """Classify a network endpoint by simulacra order."""
        result = {
            "host": host,
            "port": port,
            "banner": banner,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Check for honeypot banners (Order 3)
        for hp_name, signatures in self.HONEYPOT_INDICATORS.items():
            if any(sig in banner for sig in signatures):
                result["order"] = 3
                result["classification"] = "Honeypot Simulacrum"
                result["description"] = f"Service masks absence of reality (probable {hp_name})"
                result["confidence"] = "HIGH"
                return result

        # Check for banner/port mismatch (Order 2)
        if port in self.AUTHENTIC_SERVICES:
            expected = self.AUTHENTIC_SERVICES[port]
            if banner and expected.lower() not in banner.lower():
                result["order"] = 2
                result["classification"] = "Perverted Service"
                result["description"] = f"Port {port} claims {expected} but banner suggests otherwise"
                result["confidence"] = "MEDIUM"
                return result

        # Authentic service (Order 1)
        if port in self.AUTHENTIC_SERVICES:
            result["order"] = 1
            result["classification"] = "Authentic Service"
            result["description"] = f"Legitimate {self.AUTHENTIC_SERVICES[port]} service"
            result["confidence"] = "MEDIUM"
            return result

        # Unknown / user service
        result["order"] = 0
        result["classification"] = "Unclassified Endpoint"
        result["description"] = "Service exists outside standard taxonomy"
        result["confidence"] = "LOW"
        return result

    def grab_banner(self, host, port, timeout=3):
        """Attempt to grab a service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            # Send HTTP probe for web ports
            if port in (80, 8080, 8443, 443):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()
            return banner
        except (socket.error, socket.timeout, ConnectionRefusedError):
            return ""

    def scan_host_simulacra(self, host, ports=None):
        """Scan a host and classify all open ports by simulacra order."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
                     3306, 5432, 6379, 8080, 8443]

        results = []
        open_ports = set()

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.add(port)
                    banner = self.grab_banner(host, port)
                    classification = self.classify_endpoint(host, port, banner)
                    results.append(classification)
                sock.close()
            except (socket.error, OSError):
                continue

        # Check for trap pattern (too many services = Order 3)
        for trap in self.TRAP_PATTERNS:
            if len(open_ports & trap) >= 6:
                return {
                    "host": host,
                    "scan_time": datetime.utcnow().isoformat(),
                    "warning": "PROBABLE HONEYPOT — Excessive service exposure",
                    "order_override": 3,
                    "open_ports": len(open_ports),
                    "results": results,
                }

        return {
            "host": host,
            "scan_time": datetime.utcnow().isoformat(),
            "open_ports": len(open_ports),
            "by_order": {
                i: len([r for r in results if r["order"] == i])
                for i in range(5)
            },
            "results": results,
        }


class DNSSimulacra:
    """Analyze DNS responses for simulation depth."""

    def check_dns_authenticity(self, domain, nameserver="8.8.8.8"):
        """Check if DNS responses are authentic or simulated."""
        try:
            answers = socket.getaddrinfo(domain, None)
            ips = list(set(addr[4][0] for addr in answers))

            result = {
                "domain": domain,
                "resolved_ips": ips,
                "timestamp": datetime.utcnow().isoformat(),
            }

            # Check for sinkhole indicators
            sinkhole_ranges = [
                "0.0.0.0", "127.0.0.1", "127.0.0.2",
                "192.0.2.", "198.51.100.", "203.0.113.",  # Documentation ranges
            ]
            for ip in ips:
                if any(ip.startswith(s) for s in sinkhole_ranges):
                    result["order"] = 3
                    result["classification"] = "DNS Sinkhole"
                    result["description"] = "Domain resolves to sinkhole — masks absence of real host"
                    return result

            # Multiple IPs could indicate CDN (authentic simulation)
            if len(ips) > 3:
                result["order"] = 2
                result["classification"] = "CDN/Load Balanced"
                result["description"] = "Multiple copies — industrial reproduction of the original"
                return result

            result["order"] = 1
            result["classification"] = "Direct Resolution"
            result["description"] = "Domain maps faithfully to host"
            return result

        except socket.gaierror:
            return {
                "domain": domain,
                "order": 4,
                "classification": "Phantom Domain",
                "description": "Domain has no relation to any reality — NXDOMAIN",
            }
