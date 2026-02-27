import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import parse_qsl, quote, urlparse


REQUIRED_OAUTH_FIELDS = {
    "oauth_consumer_key",
    "oauth_nonce",
    "oauth_signature",
    "oauth_signature_method",
    "oauth_timestamp",
}


class LTIValidationError(Exception):
    pass


@dataclass
class NonceStore:
    ttl_seconds: int = 300
    _entries: dict[tuple[str, str], int] = field(default_factory=dict)

    def _purge(self, now: int) -> None:
        expired = [
            key for key, expires_at in self._entries.items() if expires_at <= now
        ]
        for key in expired:
            self._entries.pop(key, None)

    def seen(self, consumer_key: str, nonce: str, now: int | None = None) -> bool:
        now = int(now or time.time())
        self._purge(now)
        cache_key = (consumer_key, nonce)
        if cache_key in self._entries:
            return True
        self._entries[cache_key] = now + self.ttl_seconds
        return False


def oauth_percent_encode(value: object) -> str:
    return quote(str(value), safe="~-._")


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port

    include_port = False
    if port is not None:
        include_port = not (
            (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        )

    netloc = hostname
    if include_port:
        netloc = f"{hostname}:{port}"

    path = parsed.path or "/"
    return f"{scheme}://{netloc}{path}"


def _normalized_parameter_string(items: Iterable[tuple[str, str]]) -> str:
    encoded: list[tuple[str, str]] = []
    for key, value in items:
        if key == "oauth_signature":
            continue
        encoded.append((oauth_percent_encode(key), oauth_percent_encode(value)))

    encoded.sort(key=lambda pair: (pair[0], pair[1]))
    return "&".join(f"{key}={value}" for key, value in encoded)


def build_signature_base_string(
    method: str,
    url: str,
    body_items: Iterable[tuple[str, str]],
) -> str:
    parsed = urlparse(url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    all_items = list(query_items) + list(body_items)
    parameter_string = _normalized_parameter_string(all_items)
    normalized = normalize_url(url)
    return "&".join(
        [
            method.upper(),
            oauth_percent_encode(normalized),
            oauth_percent_encode(parameter_string),
        ]
    )


def compute_hmac_sha1_signature(base_string: str, consumer_secret: str) -> str:
    signing_key = f"{oauth_percent_encode(consumer_secret)}&"
    digest = hmac.new(
        signing_key.encode("utf-8"),
        base_string.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode("utf-8")


def sign_lti_launch(url: str, key: str, secret: str, params: dict[str, object]) -> dict[str, str]:
    """Sign an LTI 1.1 launch using OAuth 1.0 HMAC-SHA1.

    Returns form fields (body params) including oauth_* values.
    Query string parameters remain on the action URL and are included in the signature.
    """
    clean_params = {k: str(v) for k, v in params.items() if v is not None}
    oauth_fields = {
        "oauth_consumer_key": key,
        "oauth_nonce": secrets.token_hex(16),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_version": "1.0",
    }

    signature_items = list(clean_params.items()) + list(oauth_fields.items())
    base_string = build_signature_base_string("POST", url, signature_items)
    oauth_fields["oauth_signature"] = compute_hmac_sha1_signature(base_string, secret)

    return {**clean_params, **oauth_fields}


def validate_lti_launch(
    method: str,
    url: str,
    form_items: list[tuple[str, str]],
    consumer_secret: str,
    nonce_store: NonceStore,
    timestamp_skew_seconds: int = 300,
) -> tuple[bool, str]:
    params = dict(form_items)

    missing = [field for field in REQUIRED_OAUTH_FIELDS if not params.get(field)]
    if missing:
        return False, f"Missing OAuth fields: {', '.join(sorted(missing))}"

    if params.get("oauth_signature_method") != "HMAC-SHA1":
        return False, "Unsupported oauth_signature_method (expected HMAC-SHA1)"

    try:
        timestamp = int(params["oauth_timestamp"])
    except ValueError:
        return False, "Invalid oauth_timestamp"

    now = int(time.time())
    if abs(now - timestamp) > timestamp_skew_seconds:
        return False, "oauth_timestamp is outside the allowed clock skew"

    consumer_key = params["oauth_consumer_key"]
    nonce = params["oauth_nonce"]
    if nonce_store.seen(consumer_key, nonce, now=now):
        return False, "oauth_nonce has already been used"

    base_string = build_signature_base_string(method, url, form_items)
    expected = compute_hmac_sha1_signature(base_string, consumer_secret)
    provided = params["oauth_signature"]

    if not hmac.compare_digest(expected, provided):
        return False, "OAuth signature mismatch"

    # Lightweight LTI sanity checks for a launch request.
    if params.get("lti_message_type") and params["lti_message_type"] != "basic-lti-launch-request":
        return False, "Unsupported lti_message_type"
    if params.get("lti_version") and params["lti_version"] != "LTI-1p0":
        return False, "Unsupported lti_version"

    return True, "OK"
