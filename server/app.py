"""
Flask fallback API server — mirrors the Cloudflare Worker endpoints.
Serves both the static frontend and the /api/* endpoints.

Usage:
    cd server && uv run python app.py
    # or: uv run flask --app app run --port 8080
"""

import json
import os
import re
import socket
import ssl
import struct
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS

import dns.resolver

app = Flask(__name__, static_folder=None)
CORS(app)

FRONTEND_DIR = Path(__file__).resolve().parent.parent

BLOCKED = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|localhost|.*\.local$|.*\.internal$)"
)


def is_blocked(host: str) -> bool:
    return bool(BLOCKED.match(host))


# ─── Static file serving with required headers ───────────────────
@app.route("/")
@app.route("/<path:filepath>")
def serve_static(filepath="index.html"):
    resp = send_from_directory(str(FRONTEND_DIR), filepath)
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    if filepath.endswith(".wasm"):
        resp.content_type = "application/wasm"
    return resp


# ─── DNS ──────────────────────────────────────────────────────────
@app.route("/api/dns")
def api_dns():
    domain = request.args.get("domain")
    rtype = request.args.get("type", "A")
    if not domain:
        return jsonify(error="Missing domain parameter"), 400

    try:
        answers_list = []
        result = dns.resolver.resolve(domain, rtype)
        for rdata in result:
            answers_list.append(
                {
                    "name": domain,
                    "type": rtype,
                    "TTL": result.rrset.ttl if result.rrset else 0,
                    "data": rdata.to_text(),
                }
            )
        return jsonify(domain=domain, type=rtype, answers=answers_list)
    except dns.resolver.NXDOMAIN:
        return jsonify(domain=domain, type=rtype, answers=[])
    except dns.resolver.NoAnswer:
        return jsonify(domain=domain, type=rtype, answers=[])
    except Exception as e:
        return jsonify(error=str(e)), 502


# ─── SSL ──────────────────────────────────────────────────────────
@app.route("/api/ssl")
def api_ssl():
    host = request.args.get("host")
    port = int(request.args.get("port", 443))
    if not host:
        return jsonify(error="Missing host parameter"), 400
    if is_blocked(host):
        return jsonify(error="Host not allowed"), 403

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                certs = []
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    sans = [
                        v for t, v in cert.get("subjectAltName", ()) if t == "DNS"
                    ]
                    certs.append(
                        {
                            "subject": subject.get("commonName", ""),
                            "issuer": issuer.get("commonName", ""),
                            "validFrom": cert.get("notBefore", ""),
                            "validTo": cert.get("notAfter", ""),
                            "sans": ", ".join(sans),
                        }
                    )

                return jsonify(
                    host=host,
                    port=port,
                    tlsVersion=version,
                    cipher=cipher[0] if cipher else None,
                    certificates=certs,
                )
    except Exception as e:
        return jsonify(error=f"SSL check failed: {e}"), 502


# ─── Headers ──────────────────────────────────────────────────────
@app.route("/api/headers")
def api_headers():
    import requests as req

    url = request.args.get("url")
    if not url:
        return jsonify(error="Missing url parameter"), 400

    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return jsonify(error="Only HTTP/HTTPS allowed"), 400
        if is_blocked(parsed.hostname or ""):
            return jsonify(error="Host not allowed"), 403

        resp = req.head(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return jsonify(url=url, status=resp.status_code, headers=headers)
    except Exception as e:
        return jsonify(error=f"Fetch failed: {e}"), 502


# ─── OCSP ─────────────────────────────────────────────────────────
@app.route("/api/ocsp", methods=["POST"])
def api_ocsp():
    body = request.get_json(silent=True) or {}
    cert_pem = body.get("cert")
    issuer_pem = body.get("issuer")
    if not cert_pem:
        return jsonify(error="Missing cert field"), 400

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509 import ocsp

        cert = x509.load_pem_x509_certificate(cert_pem.encode())

        # Extract OCSP URL from AIA
        responder_url = None
        try:
            aia = cert.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            )
            for desc in aia.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    responder_url = desc.access_location.value
                    break
        except x509.ExtensionNotFound:
            pass

        if not responder_url or not issuer_pem:
            return jsonify(
                status="unknown",
                responderUrl=responder_url,
                note="Issuer certificate required for live OCSP check",
            )

        issuer = x509.load_pem_x509_certificate(issuer_pem.encode())
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA256())
        ocsp_request = builder.build()

        import requests as req

        resp = req.post(
            responder_url,
            data=ocsp_request.public_bytes(serialization.Encoding.DER),
            headers={"Content-Type": "application/ocsp-request"},
            timeout=10,
        )

        ocsp_resp = ocsp.load_der_ocsp_response(resp.content)
        status_map = {
            ocsp.OCSPCertStatus.GOOD: "good",
            ocsp.OCSPCertStatus.REVOKED: "revoked",
            ocsp.OCSPCertStatus.UNKNOWN: "unknown",
        }

        result = {
            "status": status_map.get(ocsp_resp.certificate_status, "unknown"),
            "responderUrl": responder_url,
            "producedAt": str(ocsp_resp.produced_at) if ocsp_resp.produced_at else None,
            "thisUpdate": str(ocsp_resp.this_update) if ocsp_resp.this_update else None,
            "nextUpdate": str(ocsp_resp.next_update) if ocsp_resp.next_update else None,
        }

        if ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            result["revokedAt"] = str(ocsp_resp.revocation_time)
            result["reason"] = (
                str(ocsp_resp.revocation_reason)
                if ocsp_resp.revocation_reason
                else None
            )

        return jsonify(**result)
    except Exception as e:
        return jsonify(error=f"OCSP check failed: {e}"), 502


# ─── WHOIS ────────────────────────────────────────────────────────
@app.route("/api/whois")
def api_whois():
    domain = request.args.get("domain")
    if not domain:
        return jsonify(error="Missing domain parameter"), 400

    if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
        return jsonify(error="Invalid domain format"), 400

    def whois_query(server, query):
        with socket.create_connection((server, 43), timeout=10) as s:
            s.sendall((query + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.decode("utf-8", errors="replace")

    try:
        raw = whois_query("whois.iana.org", domain)

        # Follow referral
        refer_match = re.search(r"refer:\s*(\S+)", raw, re.IGNORECASE)
        if refer_match:
            try:
                ref_raw = whois_query(refer_match.group(1), domain)
                if ref_raw.strip():
                    raw = ref_raw
            except Exception:
                pass

        parsed = {}
        patterns = {
            "Registrar": re.compile(r"registrar:\s*(.+)", re.IGNORECASE),
            "Created": re.compile(r"creat(?:ion|ed)\s*(?:date)?:\s*(.+)", re.IGNORECASE),
            "Updated": re.compile(r"updat(?:ed)?\s*(?:date)?:\s*(.+)", re.IGNORECASE),
            "Expires": re.compile(
                r"expir(?:y|ation)\s*(?:date)?:\s*(.+)", re.IGNORECASE
            ),
            "Name Servers": re.compile(r"name\s*server:\s*(.+)", re.IGNORECASE),
            "Status": re.compile(
                r"(?:domain\s*)?status:\s*(.+)", re.IGNORECASE
            ),
        }
        for label, pat in patterns.items():
            m = pat.search(raw)
            if m:
                parsed[label] = m.group(1).strip()

        return jsonify(domain=domain, raw=raw, parsed=parsed)
    except Exception as e:
        return jsonify(error=f"WHOIS lookup failed: {e}"), 502


# ─── SMTP ─────────────────────────────────────────────────────────
@app.route("/api/smtp")
def api_smtp():
    domain = request.args.get("domain")
    if not domain:
        return jsonify(error="Missing domain parameter"), 400

    # Get MX
    mx_list = []
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        for rdata in mx_records:
            mx_list.append(
                {"priority": rdata.preference, "host": str(rdata.exchange).rstrip(".")}
            )
        mx_list.sort(key=lambda x: x["priority"])
    except Exception:
        pass

    # SPF
    spf_record = None
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for rdata in txt_records:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                spf_record = txt
                break
    except Exception:
        pass

    # DMARC
    dmarc_record = None
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_records:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                dmarc_record = txt
                break
    except Exception:
        pass

    # SMTP connect
    smtp_info = None
    if mx_list:
        import smtplib

        try:
            with smtplib.SMTP(mx_list[0]["host"], 587, timeout=10) as server:
                banner = str(server.ehlo_resp or b"", "utf-8", errors="replace")
                starttls = False
                try:
                    server.starttls()
                    starttls = True
                except Exception:
                    pass
                smtp_info = {"banner": banner[:500], "starttls": starttls}
        except Exception:
            try:
                with smtplib.SMTP(mx_list[0]["host"], 25, timeout=10) as server:
                    banner = str(server.ehlo_resp or b"", "utf-8", errors="replace")
                    smtp_info = {"banner": banner[:500], "starttls": False}
            except Exception:
                smtp_info = {"banner": "(connection failed)", "starttls": False}

    return jsonify(
        domain=domain,
        mx=mx_list,
        smtp=smtp_info,
        spf={"found": bool(spf_record), "record": spf_record},
        dkim={
            "found": False,
            "note": "DKIM selector required — check selector1._domainkey",
        },
        dmarc={"found": bool(dmarc_record), "record": dmarc_record},
    )


# ─── Port Scanner ────────────────────────────────────────────────
@app.route("/api/portscan")
def api_portscan():
    host = request.args.get("host")
    ports_str = request.args.get("ports")
    if not host or not ports_str:
        return jsonify(error="Missing host or ports parameter"), 400
    if is_blocked(host):
        return jsonify(error="Host not allowed"), 403

    ports = [
        int(p.strip())
        for p in ports_str.split(",")
        if p.strip().isdigit() and 0 < int(p.strip()) <= 65535
    ]
    if not ports:
        return jsonify(error="No valid ports specified"), 400
    if len(ports) > 20:
        return jsonify(error="Maximum 20 ports per scan"), 400

    results = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                banner = ""
                try:
                    s.settimeout(2)
                    data = s.recv(512)
                    banner = data.decode("utf-8", errors="replace").strip()[:200]
                except Exception:
                    pass
                results.append({"port": port, "open": True, "banner": banner})
        except Exception:
            results.append({"port": port, "open": False, "banner": ""})

    return jsonify(host=host, results=results)


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=True)


if __name__ == "__main__":
    main()
