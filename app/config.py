import os
from dotenv import load_dotenv

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "lti-mvp")
PORT = int(os.getenv("PORT", "7999"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
# Optional external LTI endpoint to launch to (e.g. Avery)
LTI_URL = os.getenv("LTI_URL", "").rstrip("/")
NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "300"))
TIMESTAMP_SKEW_SECONDS = int(os.getenv("TIMESTAMP_SKEW_SECONDS", "300"))


def load_lti_credentials() -> dict[str, dict[str, str]]:
    """Load LTI 1.1 consumer credentials from env vars.

    Expected variables:
      - LTI_CONSUMER_KEY_1 / LTI_SHARED_SECRET_1
      - LTI_CONSUMER_KEY_2 / LTI_SHARED_SECRET_2
      - ...
    """
    consumers: dict[str, dict[str, str]] = {}
    i = 1
    while True:
        key = os.getenv(f"LTI_CONSUMER_KEY_{i}")
        secret = os.getenv(f"LTI_SHARED_SECRET_{i}")
        if not key or not secret:
            break
        consumers[key] = {"secret": secret}
        i += 1
    return consumers


LTI_CONSUMERS = load_lti_credentials()
FIRST_LTI_CONSUMER_KEY = next(iter(LTI_CONSUMERS), None)
