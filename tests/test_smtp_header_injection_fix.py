import unittest

from fixes.smtp_header_injection_fix import (
    HeaderInjectionError,
    build_contact_email,
    sanitize_email_address,
    sanitize_header_name,
    sanitize_header_value,
)


class SMTPHeaderInjectionFixTests(unittest.TestCase):
    def test_rejects_crlf_header_value_injection(self):
        with self.assertRaises(HeaderInjectionError):
            sanitize_header_value("Hello\r\nBcc: victim@example.com", field="Subject")

    def test_rejects_control_characters(self):
        with self.assertRaises(HeaderInjectionError):
            sanitize_header_value("Hello\x00World", field="Subject")

    def test_rejects_malicious_email_address(self):
        with self.assertRaises(HeaderInjectionError):
            sanitize_email_address("attacker@example.com\nCc: victim@example.com")

    def test_rejects_invalid_header_name(self):
        with self.assertRaises(HeaderInjectionError):
            sanitize_header_name("Subject\r\nBcc")

    def test_build_contact_email_uses_safe_headers(self):
        message = build_contact_email(
            sender_email="user@example.com",
            subject="Need help",
            body="This body can contain\nnewlines safely.",
            support_email="support@example.com",
            application_from="no-reply@example.com",
        )

        self.assertEqual(message["From"], "no-reply@example.com")
        self.assertEqual(message["To"], "support@example.com")
        self.assertEqual(message["Reply-To"], "user@example.com")
        self.assertEqual(message["Subject"], "Need help")
        self.assertIn("This body can contain", message.get_content())

    def test_malicious_subject_is_not_serialized_as_header(self):
        with self.assertRaises(HeaderInjectionError):
            build_contact_email(
                sender_email="user@example.com",
                subject="Hi\r\nBcc: victim@example.com",
                body="body",
                support_email="support@example.com",
            )


if __name__ == "__main__":
    unittest.main()
