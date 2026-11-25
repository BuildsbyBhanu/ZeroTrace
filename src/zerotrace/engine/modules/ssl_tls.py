"""SSL/TLS configuration analysis module."""

from __future__ import annotations

import ssl
import socket
import json
from datetime import datetime
from typing import Optional

from zerotrace.engine.base import BaseModule, FindingStatus, Severity
from zerotrace.engine.context import ScanContext
from zerotrace.logging_config import get_logger

logger = get_logger("ssl_module")

# Minimum acceptable TLS versions
MIN_TLS_VERSIONS = {
    "TLSv1.2": (3, 3),
    "TLSv1.3": (3, 4),
}

WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED", "CAMELLIA",
]


class SSLTLSModule(BaseModule):
    """Analyzes SSL/TLS certificate and configuration security."""

    name = "ssl-tls"
    description = "Checks SSL/TLS configuration, certificate validity, and cipher strength"
    owasp_category = "A02"
    severity_base = Severity.MEDIUM
    run_in_quick = True
    run_in_standard = True

    async def execute(self, context: ScanContext) -> list:
        findings = []
        hostname = context.target.base_url.split("//")[1].split(":")[0]
        port = 443 if context.target.base_url.startswith("https") else 80

        try:
            # Test TLS connection
            cert_info = await self._test_tls_connection(hostname, port)

            if cert_info:
                findings.extend(self._analyze_certificate(cert_info, hostname))
                findings.extend(self._analyze_protocol_support(hostname, port))
                findings.extend(self._analyze_cipher_strength(cert_info, hostname))
            else:
                # Try HTTP fallback for non-TLS sites
                if context.target.base_url.startswith("http://"):
                    findings.append(self._make_finding(
                        title="Website Not Using HTTPS",
                        category="A02",
                        severity=Severity.MEDIUM,
                        status=FindingStatus.CONFIRMED,
                        affected_url=context.target.normalized_url,
                        evidence="The site is accessible only over HTTP, not HTTPS.",
                        impact="Data transmitted between the user and server is sent in cleartext, vulnerable to interception.",
                        remediation="Configure the server to use HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                    ))
        except Exception as exc:
            logger.error(f"SSL/TLS check failed for {hostname}: {exc}")

        return findings

    async def _test_tls_connection(self, hostname: str, port: int) -> Optional[dict]:
        """Test TLS connection and extract certificate information."""
        loop = __import__('asyncio').get_event_loop()
        return await loop.run_in_executor(None, self._sync_test_tls, hostname, port)

    def _sync_test_tls(self, hostname: str, port: int) -> Optional[dict]:
        """Synchronous TLS connection test."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if cert:
                        import OpenSSL.crypto
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                        subject = dict(x509.get_subject().__dict__)
                        issuer = dict(x509.get_issuer().__dict__)
                        not_before = datetime.strptime(
                            x509.get_notBefore().decode(), "%Y%m%d%H%M%SZ"
                        )
                        not_after = datetime.strptime(
                            x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ"
                        )
                        return {
                            "subject": subject,
                            "issuer": issuer,
                            "not_before": not_before.isoformat(),
                            "not_after": not_after.isoformat(),
                            "version": x509.get_version(),
                            "serial": hex(x509.get_serialNumber()),
                            "cipher": ssock.cipher()[0] if ssock.cipher() else "unknown",
                            "protocol": ssock.version(),
                            "has_cert": True,
                        }
                    return {"has_cert": False}
        except ImportError:
            # Fallback: use ssl.get_server_certificate
            try:
                cert_pem = ssl.get_server_certificate((hostname, port), timeout=10)
                import cryptography.x509 as x509_mod
                from cryptography.hazmat.primitives import serialization
                cert = x509_mod.load_pem_x509_certificate(cert_pem.encode())
                return {
                    "subject": {k.value: v for k, v in cert.subject},
                    "issuer": {k.value: v for k, v in cert.issuer},
                    "not_before": cert.not_valid_before_utc.isoformat(),
                    "not_after": cert.not_valid_after_utc.isoformat(),
                    "version": cert.version,
                    "serial": hex(cert.serial_number),
                    "has_cert": True,
                    "cipher": "unknown",
                    "protocol": "unknown",
                }
            except Exception:
                return None
        except Exception:
            return None

    def _analyze_certificate(self, cert_info: dict, hostname: str) -> list:
        """Analyze certificate properties for security issues."""
        findings = []

        # Check expiration
        not_after = datetime.fromisoformat(cert_info["not_after"])
        if not_after < datetime.now():
            findings.append(self._make_finding(
                title="Expired SSL/TLS Certificate",
                category="A02",
                severity=Severity.CRITICAL,
                status=FindingStatus.CONFIRMED,
                affected_url=hostname,
                evidence=f"Certificate for '{hostname}' expired on {cert_info['not_after']}. Current date is {datetime.now().isoformat()}.",
                impact="Browsers will show security warnings to users. Man-in-the-middle attacks become trivially easy as connections cannot be securely authenticated.",
                remediation="Renew the SSL certificate immediately and deploy it to the server. Verify the new certificate is properly installed by checking the expiration date.",
                references=["https://ssl-config.mozilla.org/"],
            ))
        elif (not_after - datetime.now()).days < 30:
            findings.append(self._make_finding(
                title="SSL/TLS Certificate Expiring Soon",
                category="A02",
                severity=Severity.HIGH,
                status=FindingStatus.REQUIRES_MANUAL_VERIFICATION,
                affected_url=hostname,
                evidence=f"Certificate for '{hostname}' expires in {(not_after - datetime.now()).days} days on {cert_info['not_after']}.",
                impact="Potential for service disruption and security warnings to users. May cause certificate errors if not renewed in time.",
                remediation="Renew the certificate before expiry. Set up monitoring/alerts for certificate expiration at least 60 days before expiry.",
                references=["https://ssl-config.mozilla.org/", "https://tools.ietf.org/html/rfc5280#section-4.1.2.5"],
            ))

        # Common Name check
        subject = cert_info.get("subject", {})
        cn = subject.get("commonName", "")
        if cn and cn != hostname and not any(
            hostname.endswith(dom.strip("*").replace(".", "\\."))
            for dom in [cn] + self._extract_alt_names(subject)
        ):
            alt_names = ", ".join(self._extract_alt_names(subject)) or "None"
            findings.append(self._make_finding(
                title="Certificate Subject Alternative Name Mismatch",
                category="A02",
                severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                affected_url=hostname,
                evidence=f"Certificate Common Name is '{cn}', but accessed hostname is '{hostname}'. SAN extension contains: {alt_names}",
                impact="Users will see browser certificate warnings. This breaks trust and may indicate a misconfiguration or potential phishing setup where an attacker obtained a certificate for a similar domain.",
                remediation="Obtain a certificate that matches the hostname exactly, or add the hostname as a Subject Alternative Name (SAN) to the existing certificate.",
                references=["https://tools.ietf.org/html/rfc5280#section-4.2.1.6", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
            ))

        return findings

    @staticmethod
    def _extract_alt_names(subject: dict) -> list:
        """Extract Subject Alternative Names from certificate subject."""
        sans = []
        for key, value in subject.items():
            if "dns" in str(key).lower():
                san_value = str(value)
                if "," in san_value:
                    sans.extend([s.strip() for s in san_value.split(",")])
                else:
                    sans.append(san_value)
        return sans

    def _analyze_protocol_support(self, hostname: str, port: int) -> list:
        """Test which TLS protocol versions are supported."""
        findings = []
        weak_protocols = ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]

        for proto in weak_protocols:
            try:
                ctx = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{proto.replace('.', '_')}"))
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    ctx.wrap_socket(sock, server_hostname=hostname)
                    findings.append(self._make_finding(
                        title=f"Weak/Insecure TLS Protocol Supported: {proto}",
                        category="A02",
                        severity=Severity.CRITICAL,
                        status=FindingStatus.CONFIRMED,
                        affected_url=hostname,
                        evidence=f"Server accepts connection using deprecated protocol '{proto}'. These protocols have known cryptographic weaknesses.",
                        impact=f"The {proto} protocol has known vulnerabilities (POODLE, BEAST, CRIME, etc.) and should not be used. Attackers could exploit these weaknesses.",
                        remediation=f"Disable {proto} on the server. Only TLSv1.2 and TLSv1.3 should be enabled. Update server configuration to reject these deprecated protocols.",
                        references=["https://ssl-config.mozilla.org/"],
                    ))
                    break  # One finding per protocol family is enough
            except (AttributeError, OSError, ssl.SSLError):
                pass  # Protocol not supported — good

        return findings

    def _analyze_cipher_strength(self, cert_info: dict, hostname: str) -> list:
        """Analyze the cipher suite used for the connection."""
        findings = []
        cipher = cert_info.get("cipher", "")
        
        if cipher == "unknown":
            # Could not determine cipher, skip
            return findings
        
        # Check for weak cipher patterns
        for weak_pattern in WEAK_CIPHER_PATTERNS:
            if weak_pattern.upper() in cipher.upper():
                findings.append(self._make_finding(
                    title=f"Weak Cipher Suite in Use: {cipher}",
                    category="A02",
                    severity=Severity.HIGH,
                    status=FindingStatus.CONFIRMED,
                    affected_url=hostname,
                    evidence=f"Server is using a weak cipher algorithm '{weak_pattern}' in cipher suite '{cipher}'.",
                    impact=f"The {weak_pattern} cipher has known cryptographic weaknesses and vulnerabilities. Data encrypted with this cipher may be susceptible to decryption.",
                    remediation=f"Disable {weak_pattern} ciphers on the server. Use modern cipher suites with AES-GCM, CHACHA20-POLY1305, or AES-CCM. Refer to Mozilla SSL Configuration Generator for recommended cipher suites.",
                    references=["https://ssl-config.mozilla.org/"],
                ))
                break  # Only report the first weak pattern found
        
        return findings
