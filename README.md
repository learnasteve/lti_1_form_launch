# LTI MVP (FastAPI)

A minimal LTI 1.1 launcher/receiver for testing.

## What it does
- Receives and validates LTI 1.1 launches at `POST /lti/launch`
- Verifies OAuth 1.0 HMAC-SHA1 signatures
- Checks timestamp skew and blocks nonce re-use within the running process
- Includes `/self-test` to post a signed launch
- If `LTI_URL` is set, `/self-test` posts to that external endpoint (for example Avery)
- If `LTI_URL` is blank, `/self-test` posts back to this app

## Run with Docker Compose

1. Copy the env template:
   ```bash
   cp .env.example .env
   ```
2. Set at least:
   ```env
   LTI_CONSUMER_KEY_1=your-key
   LTI_SHARED_SECRET_1=your-secret
   ```
3. For Avery, also set:
   ```env
   LTI_URL=https://dev.let.media.kyoto-u.ac.jp/avery_analytics/lti/login
   ```
4. Start it:
   ```bash
   docker compose up --build
   ```
5. Open:
   - `http://localhost:7999/`
   - `http://localhost:7999/self-test`

## Notes
- `LTI_URL` controls the outbound launch target for `/self-test`.
- `PUBLIC_BASE_URL` controls the URL this app uses for validating inbound launches to its own `/lti/launch` endpoint.
- When posting to Avery, the signature is generated against `LTI_URL`, so it must exactly match Avery's configured validation URL.
- This is intentionally stateless and does not include DB, sessions, Google auth, or any other Huanui features.
