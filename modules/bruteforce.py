def run(target: str, services: list[dict]) -> list[dict]:
	"""Return basic hardening observations from discovered open services."""
	findings = []
	port_map = {str(item.get("port", "")): item for item in services}

	if "23" in port_map:
		findings.append(
			{
				"target": target,
				"severity": "high",
				"finding": "Telnet is exposed.",
				"recommendation": "Disable Telnet and use SSH with key-based auth.",
			}
		)

	if "21" in port_map:
		findings.append(
			{
				"target": target,
				"severity": "medium",
				"finding": "FTP is exposed.",
				"recommendation": "Use SFTP/FTPS and enforce strong authentication.",
			}
		)

	if "3389" in port_map:
		findings.append(
			{
				"target": target,
				"severity": "medium",
				"finding": "RDP is Internet-reachable.",
				"recommendation": "Restrict source IPs and require MFA through a gateway.",
			}
		)

	if "3306" in port_map or "5432" in port_map:
		findings.append(
			{
				"target": target,
				"severity": "high",
				"finding": "Database service appears externally reachable.",
				"recommendation": "Limit database access to private networks and application hosts.",
			}
		)

	return findings
