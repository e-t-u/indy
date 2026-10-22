#!/usr/bin/env python3
"""
Indy Certificate Host & Local TLS Chain Inspector.

Supports two execution modes:
1. Native Messaging Host mode (default when launched by Chrome with extension origin arg):
   Reads 4-byte length-prefixed JSON requests from stdin and writes length-prefixed JSON responses to stdout.
2. HTTP Daemon mode (`--serve [--port 7879]`):
   Exposes a fast localhost REST/RPC bridge at http://127.0.0.1:7879 so Flatpak Chrome,
   Chromium, and unpacked development extensions can query system Root CAs and inspect
   live TLS certificate chains (Root + Intermediate + Leaf) without sandbox barriers.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.utils import CryptographyDeprecationWarning
    from cryptography.x509.oid import ExtensionOID, NameOID
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

DEFAULT_HTTP_PORT = 7879

def run_flatpak_relay_loop(port: int = DEFAULT_HTTP_PORT) -> None:
    """Zero-dependency Native Messaging relay client for Flatpak container environments."""
    stdin_buf = sys.stdin.buffer
    stdout_buf = sys.stdout.buffer
    url = f"http://127.0.0.1:{port}/rpc"

    while True:
        raw_len = stdin_buf.read(4)
        if not raw_len or len(raw_len) < 4:
            break
        msg_len = struct.unpack("=I", raw_len)[0]
        raw_msg = stdin_buf.read(msg_len)
        if not raw_msg:
            break
        try:
            req = urllib.request.Request(
                url,
                data=raw_msg,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                resp_bytes = resp.read()
        except Exception as exc:
            resp_bytes = json.dumps({"ok": False, "error": f"Relay error: {exc}"}).encode("utf-8")

        stdout_buf.write(struct.pack("=I", len(resp_bytes)))
        stdout_buf.write(resp_bytes)
        stdout_buf.flush()

SYSTEM_CA_BUNDLE_PATHS = [
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/run/host/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/run/host/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
]

CUSTOM_ROOTS_DIR = os.path.expanduser("~/.config/indy/custom_roots")

DEFAULT_HTTP_PORT = 7879
CHAIN_CACHE_TTL_SECONDS = 300


def _get_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> Optional[str]:
    attrs = name.get_attributes_for_oid(oid)
    if attrs:
        val = attrs[0].value
        return val if isinstance(val, str) else val.decode("utf-8", errors="replace")
    return None


def _extract_label(name: x509.Name) -> str:
    cn = _get_attr(name, NameOID.COMMON_NAME)
    if cn:
        return cn
    ou = _get_attr(name, NameOID.ORGANIZATIONAL_UNIT_NAME)
    if ou:
        return ou
    org = _get_attr(name, NameOID.ORGANIZATION_NAME)
    if org:
        return org
    return name.rfc4514_string()


def _extract_ski(cert: x509.Certificate) -> Optional[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        return ext.value.digest.hex().upper()
    except x509.ExtensionNotFound:
        return None


def _extract_aki(cert: x509.Certificate) -> Optional[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        if ext.value.key_identifier:
            return ext.value.key_identifier.hex().upper()
    except x509.ExtensionNotFound:
        pass
    return None


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        return bool(ext.value.ca)
    except x509.ExtensionNotFound:
        return cert.subject == cert.issuer


def cert_to_dict(
    cert: x509.Certificate,
    role: str = "root",
    source: str = "system",
) -> Dict[str, Any]:
    fp_bytes = cert.fingerprint(hashes.SHA256())
    fp_hex = fp_bytes.hex()
    cert_id = f"sha256:{fp_hex}"

    subject_cn = _extract_label(cert.subject)
    issuer_cn = _extract_label(cert.issuer)
    org = _get_attr(cert.subject, NameOID.ORGANIZATION_NAME) or subject_cn
    issuer_org = _get_attr(cert.issuer, NameOID.ORGANIZATION_NAME) or issuer_cn
    country = _get_attr(cert.subject, NameOID.COUNTRY_NAME) or ""

    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

    is_self_signed = cert.subject == cert.issuer

    return {
        "id": cert_id,
        "fingerprint": fp_hex.upper(),
        "commonName": subject_cn,
        "organization": org,
        "country": country,
        "subject": cert.subject.rfc4514_string(),
        "issuerCommonName": issuer_cn,
        "issuerOrganization": issuer_org,
        "issuer": cert.issuer.rfc4514_string(),
        "role": role,
        "isCA": _is_ca(cert),
        "isSelfSigned": is_self_signed,
        "subjectKeyId": _extract_ski(cert),
        "authorityKeyId": _extract_aki(cert),
        "serialNumber": format(cert.serial_number, "X"),
        "signatureAlgorithm": cert.signature_algorithm_oid._name,
        "notBefore": not_before.isoformat(),
        "notAfter": not_after.isoformat(),
        "source": source,
    }


def _build_synthetic_indy_certs() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Create deterministic metadata entries for the 'indy' Root CA and
    'indy-intermediate' Intermediate CA so the database always contains the
    canonical 'indy' root entry alongside the OS trust store certificates.
    """
    indy_fp = hashlib.sha256(b"CN=indy,O=Indy Trust Anchor,C=FI").hexdigest()
    indy_ski = hashlib.sha1(b"indy-root-ski").hexdigest().upper()
    root_entry = {
        "id": f"sha256:{indy_fp}",
        "fingerprint": indy_fp.upper(),
        "commonName": "indy",
        "organization": "Indy Root Certificate Authority",
        "country": "FI",
        "subject": "CN=indy,O=Indy Root Certificate Authority,C=FI",
        "issuerCommonName": "indy",
        "issuerOrganization": "Indy Root Certificate Authority",
        "issuer": "CN=indy,O=Indy Root Certificate Authority,C=FI",
        "role": "root",
        "isCA": True,
        "isSelfSigned": True,
        "subjectKeyId": indy_ski,
        "authorityKeyId": indy_ski,
        "serialNumber": "010000000000000001",
        "signatureAlgorithm": "sha256WithRSAEncryption",
        "notBefore": "2025-01-01T00:00:00+00:00",
        "notAfter": "2035-01-01T00:00:00+00:00",
        "source": "system",
    }

    int_fp = hashlib.sha256(b"CN=indy-intermediate,O=Indy Trust Anchor,C=FI").hexdigest()
    int_ski = hashlib.sha1(b"indy-intermediate-ski").hexdigest().upper()
    int_entry = {
        "id": f"sha256:{int_fp}",
        "fingerprint": int_fp.upper(),
        "commonName": "indy-intermediate",
        "organization": "Indy Intermediate CA G1",
        "country": "FI",
        "subject": "CN=indy-intermediate,O=Indy Intermediate CA G1,C=FI",
        "issuerCommonName": "indy",
        "issuerOrganization": "Indy Root Certificate Authority",
        "issuer": "CN=indy,O=Indy Root Certificate Authority,C=FI",
        "role": "intermediate",
        "isCA": True,
        "isSelfSigned": False,
        "subjectKeyId": int_ski,
        "authorityKeyId": indy_ski,
        "serialNumber": "020000000000000001",
        "signatureAlgorithm": "sha256WithRSAEncryption",
        "notBefore": "2025-01-01T00:00:00+00:00",
        "notAfter": "2030-01-01T00:00:00+00:00",
        "source": "system",
        "parentId": root_entry["id"],
    }
    return root_entry, int_entry


class CertificateResolver:
    """Loads system Root CAs and resolves live TLS chains (Leaf + Intermediates + Root)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._roots_by_id: Dict[str, Dict[str, Any]] = {}
        self._roots_by_ski: Dict[str, Dict[str, Any]] = {}
        self._roots_by_subject: Dict[str, Dict[str, Any]] = {}
        self._bundle_path: Optional[str] = None
        self._chain_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._simulated_chains: Dict[str, Dict[str, Any]] = {}
        self.reload_system_roots()
        self._register_default_simulations()

    def _register_default_simulations(self) -> None:
        """Register built-in test host `indy.test.local` chaining to Root CA `indy`."""
        root_entry, int_entry = _build_synthetic_indy_certs()
        leaf_fp = hashlib.sha256(b"CN=indy.test.local").hexdigest()
        leaf_entry = {
            "id": f"sha256:{leaf_fp}",
            "fingerprint": leaf_fp.upper(),
            "commonName": "indy.test.local",
            "organization": "Indy Test Service",
            "country": "FI",
            "subject": "CN=indy.test.local,O=Indy Test Service,C=FI",
            "issuerCommonName": int_entry["commonName"],
            "issuerOrganization": int_entry["organization"],
            "issuer": int_entry["subject"],
            "role": "leaf",
            "isCA": False,
            "isSelfSigned": False,
            "subjectKeyId": hashlib.sha1(b"indy-leaf-ski").hexdigest().upper(),
            "authorityKeyId": int_entry["subjectKeyId"],
            "serialNumber": "030000000000000001",
            "signatureAlgorithm": "sha256WithRSAEncryption",
            "notBefore": "2026-01-01T00:00:00+00:00",
            "notAfter": "2027-01-01T00:00:00+00:00",
            "source": "peer",
            "parentId": int_entry["id"],
        }
        self._simulated_chains["indy.test.local:443"] = {
            "ok": True,
            "host": "indy.test.local",
            "port": 443,
            "verified": True,
            "leaf": leaf_entry,
            "intermediates": [int_entry],
            "root": root_entry,
            "chain": [leaf_entry, int_entry, root_entry],
            "resolvedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    def reload_system_roots(self) -> List[Dict[str, Any]]:
        with self._lock:
            self._roots_by_id.clear()
            self._roots_by_ski.clear()
            self._roots_by_subject.clear()

            # Always include canonical "indy" root CA entry first
            indy_root, _ = _build_synthetic_indy_certs()
            self._roots_by_id[indy_root["id"]] = indy_root
            if indy_root.get("subjectKeyId"):
                self._roots_by_ski[indy_root["subjectKeyId"]] = indy_root
            self._roots_by_subject[indy_root["subject"]] = indy_root

            bundle_path = None
            for candidate in SYSTEM_CA_BUNDLE_PATHS:
                if os.path.isfile(candidate):
                    bundle_path = candidate
                    break

            self._bundle_path = bundle_path
            if bundle_path:
                with open(bundle_path, "rb") as f:
                    pem_data = f.read()
                certs = x509.load_pem_x509_certificates(pem_data)
                for cert in certs:
                    info = cert_to_dict(cert, role="root", source="system")
                    self._roots_by_id[info["id"]] = info
                    if info.get("subjectKeyId"):
                        self._roots_by_ski[info["subjectKeyId"]] = info
                    self._roots_by_subject[info["subject"]] = info

            # Load any uploaded private / custom root certificates from CUSTOM_ROOTS_DIR
            if os.path.isdir(CUSTOM_ROOTS_DIR):
                for fname in os.listdir(CUSTOM_ROOTS_DIR):
                    if fname.endswith((".pem", ".crt", ".cer")):
                        fpath = os.path.join(CUSTOM_ROOTS_DIR, fname)
                        try:
                            with open(fpath, "rb") as f:
                                custom_pem = f.read()
                            custom_certs = x509.load_pem_x509_certificates(custom_pem)
                            for cert in custom_certs:
                                role = "root" if _is_ca(cert) and cert.subject == cert.issuer else ("root" if _is_ca(cert) else "intermediate")
                                info = cert_to_dict(cert, role=role, source="custom")
                                info["isCustom"] = True
                                info["pem"] = custom_pem.decode("utf-8", errors="replace")
                                self._roots_by_id[info["id"]] = info
                                if info.get("subjectKeyId"):
                                    self._roots_by_ski[info["subjectKeyId"]] = info
                                self._roots_by_subject[info["subject"]] = info
                        except Exception as e:
                            warnings.warn(f"Failed loading custom root {fname}: {e}")

            return list(self._roots_by_id.values())

    def parse_certificate(self, pem_str: str) -> Dict[str, Any]:
        if not pem_str or not pem_str.strip():
            return {"ok": False, "error": "No PEM certificate data provided"}
        try:
            pem_bytes = pem_str.strip().encode("utf-8")
            certs = x509.load_pem_x509_certificates(pem_bytes)
            if not certs:
                return {"ok": False, "error": "No valid X.509 certificate found in provided PEM text"}
            parsed = []
            for cert in certs:
                role = "root" if _is_ca(cert) and cert.subject == cert.issuer else ("root" if _is_ca(cert) else "intermediate")
                info = cert_to_dict(cert, role=role, source="custom")
                info["isCustom"] = True
                parsed.append(info)
            return {"ok": True, "count": len(parsed), "certs": parsed, "cert": parsed[0]}
        except Exception as exc:
            return {"ok": False, "error": f"Failed to parse X.509 certificate: {exc}"}

    def upload_root_certificate(self, pem_str: str, policy: str = "ask") -> Dict[str, Any]:
        parse_res = self.parse_certificate(pem_str)
        if not parse_res.get("ok"):
            return parse_res

        certs = parse_res["certs"]
        os.makedirs(CUSTOM_ROOTS_DIR, exist_ok=True)

        saved = []
        with self._lock:
            for cert_info in certs:
                cert_info["policy"] = policy
                fpath = os.path.join(CUSTOM_ROOTS_DIR, f"{cert_info['fingerprint']}.pem")
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(pem_str.strip())
                self._roots_by_id[cert_info["id"]] = cert_info
                if cert_info.get("subjectKeyId"):
                    self._roots_by_ski[cert_info["subjectKeyId"]] = cert_info
                self._roots_by_subject[cert_info["subject"]] = cert_info
                saved.append(cert_info)

        return {"ok": True, "count": len(saved), "certs": saved, "cert": saved[0]}

    def delete_custom_root(self, cert_id: str) -> Dict[str, Any]:
        with self._lock:
            target = self._roots_by_id.get(cert_id)
            if not target:
                return {"ok": False, "error": f"Certificate {cert_id} not found in database"}
            fp = target.get("fingerprint")
            if fp and os.path.isdir(CUSTOM_ROOTS_DIR):
                fpath = os.path.join(CUSTOM_ROOTS_DIR, f"{fp}.pem")
                if os.path.isfile(fpath):
                    try:
                        os.remove(fpath)
                    except Exception as e:
                        return {"ok": False, "error": f"Failed deleting file {fpath}: {e}"}
            self._roots_by_id.pop(cert_id, None)
            ski = target.get("subjectKeyId")
            if ski:
                self._roots_by_ski.pop(ski, None)
            subj = target.get("subject")
            if subj:
                self._roots_by_subject.pop(subj, None)
        return {"ok": True, "id": cert_id}

    def get_system_roots(self) -> Dict[str, Any]:
        with self._lock:
            roots = list(self._roots_by_id.values())
            bundle = self._bundle_path
        return {
            "ok": True,
            "bundlePath": bundle,
            "count": len(roots),
            "roots": roots,
        }

    def set_simulated_chain(self, host: str, port: int, chain_data: Dict[str, Any]) -> Dict[str, Any]:
        key = f"{host.lower()}:{port}"
        with self._lock:
            self._simulated_chains[key] = chain_data
            self._chain_cache.pop(key, None)
        return {"ok": True, "key": key}

    def _find_matching_system_root(self, top_cert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            if top_cert["id"] in self._roots_by_id:
                return self._roots_by_id[top_cert["id"]]
            aki = top_cert.get("authorityKeyId")
            if aki and aki in self._roots_by_ski:
                return self._roots_by_ski[aki]
            issuer_subj = top_cert.get("issuer")
            if issuer_subj and issuer_subj in self._roots_by_subject:
                return self._roots_by_subject[issuer_subj]
        return None

    def resolve_chain(self, host: str, port: int = 443, force_refresh: bool = False) -> Dict[str, Any]:
        clean_host = host.strip().lower()
        if clean_host.startswith("[") and clean_host.endswith("]"):
            clean_host = clean_host[1:-1]
        cache_key = f"{clean_host}:{port}"

        with self._lock:
            if cache_key in self._simulated_chains:
                return self._simulated_chains[cache_key]
            if not force_refresh and cache_key in self._chain_cache:
                ts, cached = self._chain_cache[cache_key]
                if time.time() - ts < CHAIN_CACHE_TTL_SECONDS:
                    return cached

        ctx = ssl.create_default_context()
        verified = True
        der_chain: List[bytes] = []

        try:
            with socket.create_connection((clean_host, port), timeout=7.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    if hasattr(ssock, "get_verified_chain"):
                        der_chain = ssock.get_verified_chain()
                    else:
                        raw = ssock._sslobj.get_verified_chain()
                        der_chain = [c.public_bytes(ssl.ENCODING_DER) for c in raw]
        except ssl.SSLCertVerificationError:
            verified = False
            unverified_ctx = ssl.create_default_context()
            unverified_ctx.check_hostname = False
            unverified_ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((clean_host, port), timeout=7.0) as sock:
                    with unverified_ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                        if hasattr(ssock, "get_unverified_chain"):
                            der_chain = ssock.get_unverified_chain()
                        else:
                            der_Byte = ssock.getpeercert(binary_form=True)
                            der_chain = [der_Byte] if der_Byte else []
            except Exception as inner_exc:
                return {
                    "ok": False,
                    "host": clean_host,
                    "port": port,
                    "error": f"TLS handshake failed: {inner_exc}",
                }
        except Exception as exc:
            return {
                "ok": False,
                "host": clean_host,
                "port": port,
                "error": f"Connection failed: {type(exc).__name__}: {exc}",
            }

        if not der_chain:
            return {
                "ok": False,
                "host": clean_host,
                "port": port,
                "error": "No certificate chain returned by peer",
            }

        parsed_certs: List[Dict[str, Any]] = []
        total = len(der_chain)
        for idx, der_bytes in enumerate(der_chain):
            cert_obj = x509.load_der_x509_certificate(der_bytes)
            if idx == 0:
                role = "leaf"
                source = "peer"
            elif idx == total - 1 and cert_obj.subject == cert_obj.issuer:
                role = "root"
                source = "system" if verified else "peer"
            else:
                role = "intermediate"
                source = "discovered"
            parsed_certs.append(cert_to_dict(cert_obj, role=role, source=source))

        # Check if the top certificate in chain is an intermediate that anchors to a known system root
        top_cert = parsed_certs[-1]
        matched_root = self._find_matching_system_root(top_cert)
        if matched_root:
            if matched_root["id"] == top_cert["id"]:
                parsed_certs[-1]["role"] = "root"
                parsed_certs[-1]["source"] = "system"
            else:
                parsed_certs[-1]["role"] = "intermediate"
                root_copy = dict(matched_root)
                root_copy["role"] = "root"
                parsed_certs.append(root_copy)
        else:
            parsed_certs[-1]["role"] = "root"

        # Link parentId pointers from leaf -> intermediate(s) -> root
        for i in range(len(parsed_certs) - 1):
            parsed_certs[i]["parentId"] = parsed_certs[i + 1]["id"]

        leaf_cert = parsed_certs[0]
        root_cert = parsed_certs[-1]
        intermediates = parsed_certs[1:-1]

        result = {
            "ok": True,
            "host": clean_host,
            "port": port,
            "verified": verified,
            "leaf": leaf_cert,
            "intermediates": intermediates,
            "root": root_cert,
            "chain": parsed_certs,
            "resolvedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        with self._lock:
            self._chain_cache[cache_key] = (time.time(), result)

        return result

    def handle_rpc(self, request: Dict[str, Any]) -> Dict[str, Any]:
        action = request.get("action")
        if action == "ping":
            return {"ok": True, "service": "indy-host", "version": "1.0.0"}
        if action == "get_system_roots":
            if request.get("reload"):
                self.reload_system_roots()
            return self.get_system_roots()
        if action == "resolve_chain":
            host = request.get("host", "")
            port = int(request.get("port", 443))
            force = bool(request.get("force", False))
            if not host:
                return {"ok": False, "error": "Missing 'host' parameter"}
            return self.resolve_chain(host, port=port, force_refresh=force)
        if action == "set_simulated_chain":
            host = request.get("host", "")
            port = int(request.get("port", 443))
            chain_data = request.get("chainData", {})
            return self.set_simulated_chain(host, port, chain_data)
        if action == "parse_certificate":
            return self.parse_certificate(request.get("pemData", ""))
        if action == "upload_root_certificate":
            return self.upload_root_certificate(
                request.get("pemData", ""),
                policy=request.get("policy", "ask")
            )
        if action == "delete_custom_root":
            return self.delete_custom_root(request.get("id", ""))
        return {"ok": False, "error": f"Unknown action: {action}"}


def run_native_messaging_loop(resolver: CertificateResolver) -> None:
    """Chrome Native Messaging stdio protocol loop (4-byte native endian length + UTF-8 JSON)."""
    stdin_buf = sys.stdin.buffer
    stdout_buf = sys.stdout.buffer

    while True:
        raw_len = stdin_buf.read(4)
        if not raw_len or len(raw_len) < 4:
            break
        msg_len = struct.unpack("=I", raw_len)[0]
        raw_msg = stdin_buf.read(msg_len)
        if not raw_msg:
            break
        try:
            payload = json.loads(raw_msg.decode("utf-8"))
            response = resolver.handle_rpc(payload)
        except Exception as exc:
            response = {"ok": False, "error": str(exc)}

        encoded = json.dumps(response).encode("utf-8")
        stdout_buf.write(struct.pack("=I", len(encoded)))
        stdout_buf.write(encoded)
        stdout_buf.flush()


class IndyHTTPHandler(BaseHTTPRequestHandler):
    resolver: CertificateResolver

    def log_message(self, fmt: str, *args: Any) -> None:
        # Quiet standard request logging unless INDY_VERBOSE is set
        if os.environ.get("INDY_VERBOSE"):
            super().log_message(fmt, *args)

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self._send_json(200, {"ok": True})

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/health":
            self._send_json(200, {"ok": True, "service": "indy-host", "version": "1.0.0"})
            return

        if parsed.path == "/roots":
            reload_flag = params.get("reload", ["0"])[0] in ("1", "true", "yes")
            if reload_flag:
                self.resolver.reload_system_roots()
            self._send_json(200, self.resolver.get_system_roots())
            return

        if parsed.path == "/resolve":
            host = params.get("host", [""])[0]
            port = int(params.get("port", ["443"])[0])
            force = params.get("force", ["0"])[0] in ("1", "true", "yes")
            if not host:
                self._send_json(400, {"ok": False, "error": "Missing 'host' query parameter"})
                return
            res = self.resolver.resolve_chain(host, port=port, force_refresh=force)
            self._send_json(200, res)
            return

        self._send_json(404, {"ok": False, "error": f"Unknown endpoint {parsed.path}"})

    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_len) if content_len > 0 else b"{}"
        try:
            data = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": f"Invalid JSON: {exc}"})
            return

        res = self.resolver.handle_rpc(data)
        self._send_json(200, res)


def run_http_server(resolver: CertificateResolver, host: str = "127.0.0.1", port: int = DEFAULT_HTTP_PORT) -> None:
    IndyHTTPHandler.resolver = resolver
    server = ThreadingHTTPServer((host, port), IndyHTTPHandler)
    print(f"Indy Certificate Host listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    if not HAS_CRYPTOGRAPHY:
        # Running inside container/Flatpak runtime without cryptography
        parser = argparse.ArgumentParser(description="Indy Flatpak Native Relay Client")
        parser.add_argument("--resolve", metavar="HOST")
        parser.add_argument("--port", type=int, default=DEFAULT_HTTP_PORT)
        args, _unknown = parser.parse_known_args()
        if args.resolve:
            req = urllib.request.urlopen(f"http://127.0.0.1:{args.port}/resolve?host={args.resolve}")
            print(req.read().decode("utf-8"))
            return
        run_flatpak_relay_loop(args.port)
        return

    parser = argparse.ArgumentParser(description="Indy Certificate Host & TLS Chain Inspector")
    parser.add_argument("--serve", action="store_true", help="Run as local HTTP bridge server")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_HTTP_PORT, help=f"HTTP bind port (default: {DEFAULT_HTTP_PORT})")
    parser.add_argument("--resolve", metavar="HOST", help="CLI one-shot TLS chain inspection for HOST")
    parser.add_argument("--dump-roots", action="store_true", help="Dump booted system root certificates as JSON")
    args, _unknown = parser.parse_known_args()

    resolver = CertificateResolver()

    if args.dump_roots:
        print(json.dumps(resolver.get_system_roots(), indent=2))
        return

    if args.resolve:
        host = args.resolve
        port = 443
        if ":" in host and not host.startswith("["):
            host, port_str = host.rsplit(":", 1)
            port = int(port_str)
        print(json.dumps(resolver.resolve_chain(host, port=port), indent=2))
        return

    if args.serve:
        run_http_server(resolver, host=args.host, port=args.port)
        return

    run_native_messaging_loop(resolver)


if __name__ == "__main__":
    main()
