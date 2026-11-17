"""Tests for the standalone PhishScan detector. Run: python -m unittest tests.test_analyzer"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyzer import (  # noqa: E402
    VERDICT_CLEAN,
    VERDICT_PHISHING,
    VERDICT_SUSPICIOUS,
    analyze_eml_bytes,
    analyze_text,
    analyze_url,
    unwrap_security_wrapper,
)

# The Outlook / SharePoint lure that started this tool (token truncated in spirit; full path kept).
PREMIER_FIRE_LURE = (
    "https://premierfiregr-my.sharepoint.com/personal/k_pantelides_premierfire_gr/Documents/"
    "Kimon%20Pantelides%C2%A0%20%CF%83%CE%B1%CF%82%20%CE%AD%CF%83%CF%84%CE%B5%CE%B9%CE%BB%CE%B5"
    "%20%CE%AD%CE%BD%CE%B1%20%CE%B1%CF%83%CF%86%CE%B1%CE%BB%CE%AD%CF%82%20%CE%BC%CE%AE%CE%BD%CF%85%CE%BC%CE%B1."
    "%20%CE%9A%CE%AC%CE%BD%CF%84%CE%B5%20%CE%BA%CE%BB%CE%B9%CE%BA%20%CF%83%CF%84%CE%B7%CE%BD%20"
    "%CE%B5%CF%80%CE%B9%CE%BB%CE%BF%CE%B3%CE%AE%20%CE%9B%CE%AE%CF%88%CE%B7%20%CE%B5%CE%B3%CE%B3%CF%81%CE%AC%CF%86%CE%BF%CF%85"
    "%20%CE%B3%CE%B9%CE%B1%20%CE%BD%CE%B1%20%CF%84%CE%BF%20%CE%B4%CE%B5%CE%AF%CF%84%CE%B5.pdf"
    "?e=4:NWQREU&web=1&at=9"
)

NORMAL_SHARE = (
    "https://contoso-my.sharepoint.com/personal/jane_doe_contoso_com/Documents/Q3-Invoice-2026.xlsx"
)


class UrlTests(unittest.TestCase):
    def test_premier_fire_sharepoint_lure_is_phishing(self):
        r = analyze_url(PREMIER_FIRE_LURE)
        ids = {f.id for f in r.findings}
        self.assertEqual(r.verdict, VERDICT_PHISHING)
        self.assertIn("lure_filename", ids)
        self.assertIn("trusted_host_lure", ids)
        self.assertIn("invisible_char", ids)
        self.assertIn("sentence_filename", ids)
        self.assertEqual(r.host, "premierfiregr-my.sharepoint.com")
        self.assertIn("ασφαλές μήνυμα", r.filename)

    def test_normal_sharepoint_file_is_clean(self):
        r = analyze_url(NORMAL_SHARE)
        self.assertEqual(r.verdict, VERDICT_CLEAN)
        ids = {f.id for f in r.findings}
        self.assertNotIn("lure_filename", ids)
        self.assertNotIn("trusted_host_lure", ids)

    def test_english_secure_message_pdf_on_onedrive(self):
        url = (
            "https://acme-my.sharepoint.com/personal/bob_acme_com/Documents/"
            "Bob%20sent%20you%20a%20secure%20message.%20Click%20to%20view%20the%20document.pdf"
        )
        r = analyze_url(url)
        self.assertEqual(r.verdict, VERDICT_PHISHING)
        self.assertIn("lure_filename", {f.id for f in r.findings})

    def test_brand_mismatch_paypal(self):
        r = analyze_url("https://paypal-secure-login.xyz/verify/account")
        self.assertEqual(r.verdict, VERDICT_PHISHING)
        ids = {f.id for f in r.findings}
        self.assertIn("brand_mismatch", ids)
        self.assertIn("bad_tld", ids)

    def test_official_microsoft_is_clean(self):
        r = analyze_url("https://login.microsoftonline.com/")
        self.assertEqual(r.verdict, VERDICT_CLEAN)

    def test_ip_literal_is_at_least_suspicious(self):
        r = analyze_url("http://203.0.113.44/login")
        self.assertIn(r.verdict, (VERDICT_SUSPICIOUS, VERDICT_PHISHING))
        self.assertIn("ip_host", {f.id for f in r.findings})

    def test_javascript_scheme(self):
        r = analyze_url("javascript:alert(1)")
        self.assertEqual(r.verdict, VERDICT_PHISHING)
        self.assertIn("dangerous_scheme", {f.id for f in r.findings})

    def test_at_userinfo_hides_domain(self):
        r = analyze_url("https://microsoft.com@evil.example/owa")
        self.assertIn("userinfo", {f.id for f in r.findings})
        self.assertGreaterEqual(r.score, 6)

    def test_html_file_on_sharepoint(self):
        r = analyze_url(
            "https://contoso-my.sharepoint.com/personal/x_contoso_com/Documents/invoice.html"
        )
        self.assertIn("dangerous_share_ext", {f.id for f in r.findings})

    def test_shortener_is_suspicious_not_always_phishing(self):
        r = analyze_url("https://bit.ly/something")
        self.assertEqual(r.verdict, VERDICT_SUSPICIOUS)
        self.assertIn("shortener", {f.id for f in r.findings})

    def test_punycode(self):
        r = analyze_url("https://xn--pple-43d.com/login")
        self.assertIn("punycode", {f.id for f in r.findings})


class TextAndEmailTests(unittest.TestCase):
    def test_href_mismatch(self):
        html = '<a href="https://evil.example/login">https://login.microsoftonline.com</a>'
        report = analyze_text(html)
        self.assertTrue(any(f.id == "href_mismatch" for f in report.text_findings))
        self.assertIn(report.verdict, (VERDICT_SUSPICIOUS, VERDICT_PHISHING))

    def test_eml_with_sharepoint_lure(self):
        eml = (
            "From: Kimon Pantelides <k.pantelides@premierfire.gr>\r\n"
            "To: amantzari@stop.gr\r\n"
            "Subject: Kimon Pantelides shared a file with you\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Kimon Pantelides shared a file with you.\r\n"
            f"{PREMIER_FIRE_LURE}\r\n"
        ).encode("utf-8")
        report = analyze_eml_bytes(eml)
        self.assertEqual(report.verdict, VERDICT_PHISHING)
        self.assertTrue(report.urls)

    def test_unwrap_outlook_safelinks(self):
        inner = "https://example.com/doc.pdf"
        wrapped = (
            "https://nam.safelinks.protection.outlook.com/?url="
            "https%3A%2F%2Fexample.com%2Fdoc.pdf&data=abc"
        )
        got, via = unwrap_security_wrapper(wrapped)
        self.assertEqual(got, inner)
        self.assertIn("safelinks", via)

    def test_spaced_sharepoint_filename_stays_one_url(self):
        from analyzer import extract_urls
        report = analyze_text(PREMIER_FIRE_LURE.replace("%20", " "))
        self.assertEqual(len(report.urls), 1)
        self.assertEqual(report.verdict, VERDICT_PHISHING)
        self.assertIn("ασφαλές μήνυμα", report.urls[0].filename)
        extracted = extract_urls(PREMIER_FIRE_LURE.replace("%20", " "))
        self.assertEqual(len(extracted), 1)

    def test_empty_is_clean(self):
        report = analyze_text("")
        self.assertEqual(report.verdict, VERDICT_CLEAN)
        self.assertEqual(report.score, 0)


if __name__ == "__main__":
    unittest.main()
