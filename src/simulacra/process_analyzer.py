"""Simulacra Process Analyzer — Ontological classification of system processes.

Maps running processes to Baudrillard's four orders of simulacra by analyzing
their relationship to 'authentic' system behavior vs. simulated/forged identity.
"""

import os
import hashlib
import json
from datetime import datetime


class ProcessSimulacra:
    """Classify processes by their ontological relationship to authenticity."""

    # Known legitimate system process signatures (Order 1 — Faithful Copy)
    SYSTEM_ORIGINALS = {
        "init", "systemd", "kernel", "kthreadd", "ksoftirqd",
        "kworker", "rcu_sched", "migration", "watchdog",
        "sshd", "cron", "rsyslogd", "dbus-daemon",
    }

    # Processes that mimic others (Order 2 — Perverted Copy)
    MASQUERADE_PATTERNS = [
        ("svchost", "svchost.exe"),    # Windows service host mimicry
        ("csrss", "csrss.exe"),        # Often spoofed
        ("lsass", "lsass.exe"),        # Credential harvester target
        ("[kworker", "kernel_thread"),  # Kernel thread impersonation
    ]

    # Common rootkit process names (Order 4 — Pure Simulacrum)
    KNOWN_PHANTOMS = {
        "xmrig", "cryptonight", "minerd", "cpuminer",
        "azazel", "jynx", "vlany", "beurk",
        "bdvl", "libprocesshider",
    }

    def classify_process(self, name, pid, ppid, cmdline="", exe_path=""):
        """Classify a single process into an order of simulacra."""
        name_lower = name.lower().strip()
        result = {
            "name": name,
            "pid": pid,
            "ppid": ppid,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Order 4: Pure Simulacrum — known malicious / phantom
        if any(phantom in name_lower for phantom in self.KNOWN_PHANTOMS):
            result["order"] = 4
            result["classification"] = "Pure Simulacrum"
            result["description"] = "Process bears no relation to legitimate system reality"
            result["threat_level"] = "CRITICAL"
            return result

        # Order 3: Masks absence — process exists but its claimed identity is hollow
        if self._check_hollow_identity(name, exe_path, cmdline):
            result["order"] = 3
            result["classification"] = "Hollow Simulation"
            result["description"] = "Process masks the absence of genuine functionality"
            result["threat_level"] = "HIGH"
            return result

        # Order 2: Perverted Copy — resembles a system process but is subtly wrong
        masquerade = self._check_masquerade(name, exe_path)
        if masquerade:
            result["order"] = 2
            result["classification"] = "Perverted Copy"
            result["description"] = f"Process mimics '{masquerade}' but perverts its reality"
            result["threat_level"] = "MEDIUM"
            return result

        # Order 1: Faithful Copy — legitimate system process
        if name_lower in self.SYSTEM_ORIGINALS or name_lower.rstrip("0123456789/") in self.SYSTEM_ORIGINALS:
            result["order"] = 1
            result["classification"] = "Faithful Representation"
            result["description"] = "Process reflects genuine system reality"
            result["threat_level"] = "NONE"
            return result

        # Unclassified — user-space process, neutral
        result["order"] = 0
        result["classification"] = "Unclassified"
        result["description"] = "Process exists outside the simulacra taxonomy"
        result["threat_level"] = "INFO"
        return result

    def _check_hollow_identity(self, name, exe_path, cmdline):
        """Check if process claims an identity but has no substance."""
        if exe_path and not os.path.exists(exe_path):
            return True  # Claims a binary that doesn't exist
        if cmdline and cmdline.strip() == "":
            return True  # Running with empty command line
        if name.startswith("[") and name.endswith("]") and name[1:-1] not in {
            "kthreadd", "kworker", "rcu_sched", "migration",
            "ksoftirqd", "watchdog", "kcompactd", "khugepaged",
        }:
            return True  # Brackets suggest kernel thread but name unknown
        return False

    def _check_masquerade(self, name, exe_path):
        """Check if process masquerades as a known system process."""
        name_lower = name.lower()
        for pattern, real_name in self.MASQUERADE_PATTERNS:
            if pattern in name_lower:
                # Check if it's from the expected location
                if exe_path:
                    expected_paths = ["/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/",
                                     "C:\\Windows\\System32\\"]
                    if not any(exe_path.startswith(p) for p in expected_paths):
                        return real_name
        return None

    def scan_procfs(self):
        """Scan /proc for all running processes and classify them."""
        results = []
        if not os.path.exists("/proc"):
            return {"error": "No /proc filesystem — not Linux"}

        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            pid = int(pid_dir)
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    name = f.read().strip()
                with open(f"/proc/{pid}/status", "r") as f:
                    status = f.read()
                ppid = 0
                for line in status.split("\n"):
                    if line.startswith("PPid:"):
                        ppid = int(line.split(":")[1].strip())
                        break
                try:
                    exe_path = os.readlink(f"/proc/{pid}/exe")
                except (OSError, PermissionError):
                    exe_path = ""
                try:
                    with open(f"/proc/{pid}/cmdline", "r") as f:
                        cmdline = f.read().replace("\x00", " ").strip()
                except (OSError, PermissionError):
                    cmdline = ""

                result = self.classify_process(name, pid, ppid, cmdline, exe_path)
                results.append(result)
            except (FileNotFoundError, PermissionError):
                continue

        return {
            "scan_time": datetime.utcnow().isoformat(),
            "total_processes": len(results),
            "by_order": {
                i: len([r for r in results if r["order"] == i])
                for i in range(5)
            },
            "threats": [r for r in results if r["threat_level"] in ("CRITICAL", "HIGH", "MEDIUM")],
            "processes": results,
        }


class SimulacraForensics:
    """File-level simulacra analysis — detect copies, fakes, and phantoms."""

    def hash_binary(self, filepath):
        """Generate identity hash for a binary."""
        try:
            with open(filepath, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (OSError, PermissionError):
            return None

    def detect_binary_substitution(self, binary_path, known_hashes=None):
        """Check if a binary has been substituted (Order 2 attack)."""
        if not os.path.exists(binary_path):
            return {"status": "PHANTOM", "order": 3,
                    "detail": "Binary claims to exist but does not"}

        current_hash = self.hash_binary(binary_path)
        if current_hash is None:
            return {"status": "UNREADABLE", "order": 2,
                    "detail": "Binary exists but cannot be verified"}

        if known_hashes and binary_path in known_hashes:
            if current_hash != known_hashes[binary_path]:
                return {"status": "SUBSTITUTED", "order": 2,
                        "detail": "Binary hash does not match known good",
                        "expected": known_hashes[binary_path],
                        "actual": current_hash}

        stat = os.stat(binary_path)
        return {
            "status": "VERIFIED" if known_hashes else "UNKNOWN",
            "order": 1 if known_hashes and binary_path in known_hashes else 0,
            "hash": current_hash,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }

    def audit_suid_binaries(self):
        """Find SUID binaries — potential Order 2 masquerades."""
        suid_files = []
        search_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin",
                        "/usr/local/bin", "/usr/local/sbin"]
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue
            try:
                for entry in os.listdir(search_path):
                    fullpath = os.path.join(search_path, entry)
                    try:
                        st = os.stat(fullpath)
                        if st.st_mode & 0o4000:  # SUID bit
                            suid_files.append({
                                "path": fullpath,
                                "size": st.st_size,
                                "hash": self.hash_binary(fullpath),
                                "owner_uid": st.st_uid,
                            })
                    except (OSError, PermissionError):
                        continue
            except PermissionError:
                continue

        return {
            "scan_time": datetime.utcnow().isoformat(),
            "suid_count": len(suid_files),
            "binaries": suid_files,
        }
