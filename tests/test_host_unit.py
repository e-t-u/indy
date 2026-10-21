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


if __name__ == "__main__":
    unittest.main(verbosity=2)
