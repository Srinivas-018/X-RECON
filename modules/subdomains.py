import re
import socket


COMMON_SUBDOMAINS = [
	"www",
	"api",
	"dev",
	"staging",
	"admin",
	"mail",
	"vpn",
]


def _is_domain(target: str) -> bool:
	return bool(re.fullmatch(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", target or ""))


def run(target: str) -> list[dict]:
	"""Resolve a small list of common subdomains for authorized asset inventory."""
	if not _is_domain(target):
		return []

	findings = []
	socket.setdefaulttimeout(1.5)
	for sub in COMMON_SUBDOMAINS:
		hostname = f"{sub}.{target}".lower()
		try:
			ip = socket.gethostbyname(hostname)
			findings.append({"subdomain": hostname, "ip": ip, "status": "resolved"})
		except socket.gaierror:
			continue

	return findings
