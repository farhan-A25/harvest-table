"""Google sign-in (OAuth 2.0 / OpenID Connect) for the CafeLoop Owner App.

Standard library only (urllib) — no new dependencies. Configuration comes
from the environment and is read on every call:

    GOOGLE_CLIENT_ID      OAuth client ID from Google Cloud Console
    GOOGLE_CLIENT_SECRET  OAuth client secret from Google Cloud Console
    APP_BASE_URL          Public base URL of this app (default
                          http://127.0.0.1:8000). The redirect URI sent to
                          Google is {APP_BASE_URL}/auth/google/callback —
                          register exactly that URI in the Google console.

When the client ID/secret are not set, Google sign-in is simply disabled:
`google_auth_enabled()` is False, the frontend hides its button, and the
/auth/google route answers with a friendly redirect instead of an error.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
_HTTP_TIMEOUT = 10  # seconds


class GoogleAuthError(Exception):
    """Any failure talking to Google; callers turn it into a friendly page."""


def google_client_id() -> str:
    return os.environ.get("GOOGLE_CLIENT_ID", "").strip()


def google_client_secret() -> str:
    return os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()


def google_auth_enabled() -> bool:
    """Google sign-in is on only when both credentials are configured."""
    return bool(google_client_id() and google_client_secret())


def app_base_url() -> str:
    return os.environ.get("APP_BASE_URL", "http://127.0.0.1:8000").strip().rstrip("/")


def google_redirect_uri() -> str:
    return app_base_url() + "/auth/google/callback"


def build_authorize_url(state: str) -> str:
    """The Google consent-screen URL the browser is redirected to."""
    params = {
        "client_id": google_client_id(),
        "redirect_uri": google_redirect_uri(),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    return GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)


def _request_json(req: urllib.request.Request) -> dict:
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, OSError) as exc:
        raise GoogleAuthError(f"Google request failed: {exc}") from exc


def exchange_code_for_token(code: str) -> str:
    """Swap the authorization code from Google's redirect for an access token."""
    form = urllib.parse.urlencode({
        "code": code,
        "client_id": google_client_id(),
        "client_secret": google_client_secret(),
        "redirect_uri": google_redirect_uri(),
        "grant_type": "authorization_code",
    }).encode("utf-8")
    req = urllib.request.Request(
        GOOGLE_TOKEN_URL, data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    data = _request_json(req)
    token = data.get("access_token")
    if not token:
        raise GoogleAuthError("Google did not return an access token.")
    return token


def fetch_google_userinfo(access_token: str) -> dict:
    """The signed-in Google profile: email, email_verified, name, picture."""
    req = urllib.request.Request(
        GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        method="GET",
    )
    return _request_json(req)
