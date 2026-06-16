import ssl
import socket
import requests
from datetime import datetime, timezone
from core.models import Finding
from config import TIMEOUT, HEADERS

def check_ssl(url: str) -> list[Finding]:
    findings = []
    hostname = extract_hostname(url)

    # ── Check 1: HTTPS at all ─────────────────────────────────
    if url.startswith('http://'):
        findings.append(Finding(
            check_name="HTTPS Enforcement",
            category="ssl",
            passed=False,
            severity="critical",
            detail="Site is being served over HTTP, not HTTPS. All data is transmitted in plaintext.",
            fix="Enable HTTPS on your server. On Render/Railway it is automatic. On VPS use certbot: 'sudo certbot --nginx'",
            evidence=url
        ))
        # check if it redirects to https
        try:
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=True
            )
            if response.url.startswith('https://'):
                findings.append(Finding(
                    check_name="HTTP to HTTPS Redirect",
                    category="ssl",
                    passed=True,
                    severity="info",
                    detail="Site redirects HTTP to HTTPS correctly",
                    fix="No action needed",
                    evidence=response.url
                ))
            else:
                findings.append(Finding(
                    check_name="HTTP to HTTPS Redirect",
                    category="ssl",
                    passed=False,
                    severity="critical",
                    detail="Site does not redirect HTTP to HTTPS",
                    fix="Configure your server to redirect all HTTP traffic to HTTPS permanently (301 redirect)",
                    evidence=response.url
                ))
        except Exception:
            pass
        return findings

    # ── Check 2: Certificate validity ─────────────────────────
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        findings.append(Finding(
            check_name="SSL Certificate Valid",
            category="ssl",
            passed=True,
            severity="info",
            detail="SSL certificate is valid and trusted",
            fix="No action needed",
            evidence=f"Issued to: {hostname}"
        ))

        # ── Check 3: Certificate expiry ───────────────────────
        expire_date_str = cert['notAfter']
        expire_date = datetime.strptime(
            expire_date_str, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        days_left = (expire_date - datetime.now(timezone.utc)).days

        if days_left < 0:
            findings.append(Finding(
                check_name="SSL Certificate Expiry",
                category="ssl",
                passed=False,
                severity="critical",
                detail=f"SSL certificate expired {abs(days_left)} days ago",
                fix="Renew your SSL certificate immediately. On Render/Railway this is automatic. On VPS: 'sudo certbot renew'",
                evidence=f"Expired: {expire_date_str}"
            ))
        elif days_left < 30:
            findings.append(Finding(
                check_name="SSL Certificate Expiry",
                category="ssl",
                passed=False,
                severity="high",
                detail=f"SSL certificate expires in {days_left} days",
                fix="Renew your SSL certificate soon. On VPS: 'sudo certbot renew'",
                evidence=f"Expires: {expire_date_str}"
            ))
        else:
            findings.append(Finding(
                check_name="SSL Certificate Expiry",
                category="ssl",
                passed=True,
                severity="info",
                detail=f"SSL certificate is valid for {days_left} more days",
                fix="No action needed",
                evidence=f"Expires: {expire_date_str}"
            ))

    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            check_name="SSL Certificate Valid",
            category="ssl",
            passed=False,
            severity="critical",
            detail="SSL certificate is invalid or untrusted",
            fix="Get a valid SSL certificate from Let's Encrypt (free): https://letsencrypt.org",
            evidence=str(e)
        ))
    except socket.timeout:
        findings.append(Finding(
            check_name="SSL Certificate Valid",
            category="ssl",
            passed=False,
            severity="critical",
            detail=f"Connection timed out while checking SSL on {hostname}",
            fix="Check if port 443 is open and the site is reachable",
            evidence=None
        ))
    except Exception as e:
        findings.append(Finding(
            check_name="SSL Certificate Valid",
            category="ssl",
            passed=False,
            severity="critical",
            detail=f"Could not check SSL certificate: {str(e)}",
            fix="Ensure your site has a valid SSL certificate installed",
            evidence=None
        ))

    return findings


def extract_hostname(url: str) -> str:
    # strips http:// or https:// and any path
    url = url.replace("https://", "").replace("http://", "")
    return url.split("/")[0].split(":")[0]