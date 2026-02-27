# LTI MVP (FastAPI)

A minimal LTI 1.1 launch receiver for testing.

## What it does
- Receives and validates LTI 1.1 launches at `POST /lti/launch`
- Verifies OAuth 1.0 HMAC-SHA1 signatures
- Checks timestamp skew and blocks nonce re-use within the running process
- Includes `/self-test` to post a signed launch back to itself

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
3. Start it:
   ```bash
   docker compose up --build
   ```
4. Open:
   - `http://localhost:7999/`
   - `http://localhost:7999/self-test`

## Notes
- If your LMS launches to a public tunnel/proxy URL, set `PUBLIC_BASE_URL` to that exact public base URL. OAuth signatures are sensitive to the full URL.
- This is intentionally stateless and does not include DB, sessions, Google auth, or any other Huanui features.
