import unittest

from fixes.session_token_url_fix import (
    SessionTokenInUrlError,
    SessionTokenURLGuard,
    migrate_one_time_token_to_cookie,
    reject_session_tokens_in_url,
    strip_sensitive_query_params,
)


class SessionTokenURLFixTests(unittest.TestCase):
    def test_rejects_session_token_query_parameter(self):
        with self.assertRaises(SessionTokenInUrlError) as ctx:
            reject_session_tokens_in_url(
                "https://example.test/callback?session_token=secret"
            )

        self.assertIn("session_token", str(ctx.exception))

    def test_strips_sensitive_query_params_and_preserves_safe_params(self):
        result = strip_sensitive_query_params(
            "https://example.test/search?q=public&access_token=secret&page=2#top"
        )

        self.assertEqual(result.url, "https://example.test/search?q=public&page=2#top")
        self.assertEqual(result.removed_keys, ("access_token",))

    def test_allows_normal_query_parameters(self):
        url = "https://example.test/search?q=public&page=2"

        reject_session_tokens_in_url(url)
        self.assertEqual(strip_sensitive_query_params(url).url, url)

    def test_migrates_one_time_token_to_secure_cookie(self):
        clean_url, cookie = migrate_one_time_token_to_cookie(
            "https://example.test/callback?one_time_token=abc123&next=%2Fhome"
        )

        self.assertEqual(clean_url, "https://example.test/callback?next=%2Fhome")
        self.assertIsNotNone(cookie)
        self.assertIn("abc123", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_wsgi_guard_blocks_token_in_url(self):
        events = []

        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        def start_response(status, headers):
            events.append((status, dict(headers)))

        guard = SessionTokenURLGuard(app)
        body = b"".join(guard({"QUERY_STRING": "token=secret"}, start_response))

        self.assertEqual(events[-1][0], "400 Bad Request")
        self.assertEqual(events[-1][1]["Cache-Control"], "no-store")
        self.assertTrue(body.startswith(b"Session token"))

    def test_wsgi_guard_allows_normal_query(self):
        events = []

        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        def start_response(status, headers):
            events.append((status, dict(headers)))

        guard = SessionTokenURLGuard(app)
        body = b"".join(guard({"QUERY_STRING": "q=public"}, start_response))

        self.assertEqual(events[-1][0], "200 OK")
        self.assertEqual(body, b"ok")


if __name__ == "__main__":
    unittest.main()
