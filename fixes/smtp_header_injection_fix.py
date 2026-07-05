"""Fix for issue #41: prevent SMTP header injection from contact form input."""

from __future__ import annotations

import re
from email.message import EmailMessage


class HeaderInjectionError(ValueError):
    """Raised when untrusted input is unsafe for an email header."""


_HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def sanitize_header_name(name: str) -> str:
    """Allow only normal RFC-style header field names."""
    text = str(name).strip()
    if not _HEADER_NAME_RE.fullmatch(text):
        raise HeaderInjectionError(f"unsafe email header name: {name!r}")
    return text


def sanitize_header_value(value: object, *, field: str = "header", max_length: int = 998) -> str:
    """Reject CRLF, NUL, and control bytes before a value reaches SMTP headers."""
    if value is None:
        raise HeaderInjectionError(f"{field} is required")

    text = str(value).strip()
    if not text:
        raise HeaderInjectionError(f"{field} is required")
    if "\r" in text or "\n" in text:
        raise HeaderInjectionError(f"{field} contains CRLF injection bytes")
    if _CONTROL_RE.search(text):
        raise HeaderInjectionError(f"{field} contains control characters")
    if len(text) > max_length:
        raise HeaderInjectionError(f"{field} is too long")

    return re.sub(r" {2,}", " ", text)


def sanitize_email_address(value: object, *, field: str = "email") -> str:
    """Validate an untrusted email address before using it in To/Reply-To."""
    text = sanitize_header_value(value, field=field, max_length=254)
    if "," in text or "<" in text or ">" in text:
        raise HeaderInjectionError(f"{field} must be a single addr-spec")
    if not _EMAIL_RE.fullmatch(text):
        raise HeaderInjectionError(f"{field} is not a valid email address")
    return text


def set_safe_header(message: EmailMessage, name: str, value: object) -> None:
    safe_name = sanitize_header_name(name)
    safe_value = sanitize_header_value(value, field=safe_name)
    message[safe_name] = safe_value


def build_contact_email(
    *,
    sender_email: str,
    subject: str,
    body: str,
    support_email: str,
    application_from: str = "no-reply@example.com",
) -> EmailMessage:
    """Build a contact-form email without placing raw user input in headers."""
    message = EmailMessage()
    message["From"] = sanitize_email_address(application_from, field="application_from")
    message["To"] = sanitize_email_address(support_email, field="support_email")
    message["Reply-To"] = sanitize_email_address(sender_email, field="sender_email")
    set_safe_header(message, "Subject", subject)
    message.set_content(str(body or ""))
    return message


if __name__ == "__main__":
    msg = build_contact_email(
        sender_email="user@example.com",
        subject="Support request",
        body="Hello",
        support_email="support@example.com",
    )
    assert msg["Reply-To"] == "user@example.com"
    assert msg["Subject"] == "Support request"
    try:
        build_contact_email(
            sender_email="attacker@example.com\r\nBcc: victim@example.com",
            subject="hello",
            body="body",
            support_email="support@example.com",
        )
    except HeaderInjectionError:
        pass
    else:
        raise AssertionError("CRLF injection was not rejected")
