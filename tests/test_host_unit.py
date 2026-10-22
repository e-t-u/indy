#!/usr/bin/env python3
"""
Unit and Live TLS Chain Integration Tests for Indy Certificate Host.
Tests system root store bootstrapping, the "indy" root/intermediate chain,
and live TLS certificate chains (Root + Intermediates + Leaf) for the
Top 5 USA and Top 5 Indian websites.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host"))
from indy_host import CertificateResolver  # noqa: E402

TOP_5_USA_SITES = [
    "www.google.com",
    "www.youtube.com",
    "www.amazon.com",
    "www.wikipedia.org",
    "www.reddit.com",
]

TOP_5_INDIA_SITES = [
    "www.indiatimes.com",
    "www.flipkart.com",
    "www.ndtv.com",
    "www.hdfcbank.com",
    "www.icicibank.com",
]


class TestIndyCertificateHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolver = CertificateResolver()

    def test_01_system_roots_bootstrapped(self) -> None:
        res = self.resolver.get_system_roots()
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["count"], 100)
        self.assertIsNotNone(res["bundlePath"])

        cns = {r["commonName"] for r in res["roots"]}
        self.assertIn("indy", cns)
        self.assertIn("DigiCert Global Root G2", cns)
        self.assertIn("ISRG Root X1", cns)

    def test_02_indy_root_and_intermediate_chain(self) -> None:
        res = self.resolver.resolve_chain("indy.test.local", 443)
        self.assertTrue(res["ok"])
        self.assertEqual(res["root"]["commonName"], "indy")
        self.assertEqual(res["root"]["role"], "root")
        self.assertEqual(len(res["intermediates"]), 1)
        self.assertEqual(res["intermediates"][0]["commonName"], "indy-intermediate")
        self.assertEqual(res["intermediates"][0]["role"], "intermediate")
        self.assertEqual(res["intermediates"][0]["parentId"], res["root"]["id"])
        self.assertEqual(res["leaf"]["commonName"], "indy.test.local")

    def test_03_top_5_usa_websites_tls_chain(self) -> None:
        for host in TOP_5_USA_SITES:
            with self.subTest(country="USA", host=host):
                res = self.resolver.resolve_chain(host, 443)
                self.assertTrue(res["ok"], f"Failed for USA site {host}: {res.get('error')}")
                self.assertTrue(res["verified"])
                self.assertEqual(res["root"]["role"], "root")
                self.assertTrue(res["root"]["commonName"])
                self.assertGreaterEqual(len(res["intermediates"]), 1)
                for inter in res["intermediates"]:
                    self.assertEqual(inter["role"], "intermediate")
                    self.assertTrue(inter["commonName"])

    def test_04_top_5_india_websites_tls_chain(self) -> None:
        for host in TOP_5_INDIA_SITES:
            with self.subTest(country="IND", host=host):
                res = self.resolver.resolve_chain(host, 443)
                self.assertTrue(res["ok"], f"Failed for India site {host}: {res.get('error')}")
                self.assertTrue(res["verified"])
                self.assertEqual(res["root"]["role"], "root")
                self.assertTrue(res["root"]["commonName"])
                self.assertGreaterEqual(len(res["intermediates"]), 1)
                for inter in res["intermediates"]:
                    self.assertEqual(inter["role"], "intermediate")
                    self.assertTrue(inter["commonName"])

    def test_05_custom_root_lifecycle(self) -> None:
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Unit Test Private Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Indy Unit Testing Org"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        pem_str = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # 1. Parse certificate
        parsed = self.resolver.parse_certificate(pem_str)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["cert"]["commonName"], "Unit Test Private Root CA")
        self.assertEqual(parsed["cert"]["organization"], "Indy Unit Testing Org")
        self.assertTrue(parsed["cert"]["isCA"])

        # 2. Upload root certificate
        upload_res = self.resolver.upload_root_certificate(pem_str, policy="accept")
        self.assertTrue(upload_res["ok"])
        cert_id = upload_res["cert"]["id"]
        self.assertEqual(upload_res["cert"]["source"], "custom")
        self.assertEqual(upload_res["cert"]["policy"], "accept")

        # Verify it shows up in get_system_roots
        roots_res = self.resolver.get_system_roots()
        cns = {r["commonName"] for r in roots_res["roots"]}
        self.assertIn("Unit Test Private Root CA", cns)

        # 3. Delete custom root
        del_res = self.resolver.delete_custom_root(cert_id)
        self.assertTrue(del_res["ok"])

        # Verify it is removed
        roots_res_after = self.resolver.get_system_roots()
        cns_after = {r["commonName"] for r in roots_res_after["roots"]}
        self.assertNotIn("Unit Test Private Root CA", cns_after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
