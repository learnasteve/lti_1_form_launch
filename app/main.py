import html
import json

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from app.config import (
    APP_NAME,
    FIRST_LTI_CONSUMER_KEY,
    LTI_CONSUMERS,
    LTI_URL,
    NONCE_TTL_SECONDS,
    PUBLIC_BASE_URL,
    TIMESTAMP_SKEW_SECONDS,
)
from app.lti import NonceStore, sign_lti_launch, validate_lti_launch

app = FastAPI(title=APP_NAME)
nonce_store = NonceStore(ttl_seconds=NONCE_TTL_SECONDS)


def external_request_url(request: Request) -> str:
    """Build the URL that should be used for OAuth validation.

    PUBLIC_BASE_URL is the safest option when running behind a reverse proxy or tunnel.
    Otherwise, we fall back to forwarded headers and then the incoming request host.
    """
    if PUBLIC_BASE_URL:
        return f"{PUBLIC_BASE_URL}{request.url.path}"

    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    prefix = request.headers.get("x-forwarded-prefix", "")
    return f"{proto}://{host}{prefix}{request.url.path}"


def default_launch_target(request: Request) -> str:
    """Where /self-test should POST.

    If LTI_URL is configured, use it so this app can act as a launcher to another tool
    (for example Avery). Otherwise, post back to this app's own /lti/launch endpoint.
    """
    if LTI_URL:
        return LTI_URL
    return external_request_url(request).rsplit("/self-test", 1)[0] + "/lti/launch"


def html_page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    page = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset=\"utf-8\" />
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
        <title>{html.escape(title)}</title>
        <style>
          body {{ font-family: Arial, sans-serif; margin: 2rem; line-height: 1.5; }}
          code, pre {{ background: #f4f4f4; padding: 0.2rem 0.4rem; border-radius: 4px; }}
          pre {{ padding: 1rem; overflow-x: auto; }}
          table {{ border-collapse: collapse; width: 100%; max-width: 960px; }}
          th, td {{ border: 1px solid #ddd; padding: 0.5rem; text-align: left; vertical-align: top; }}
          th {{ background: #f7f7f7; width: 240px; }}
          .ok {{ color: #0a7d25; }}
          .err {{ color: #a61b1b; }}
          .muted {{ color: #666; }}
          .wrap {{ word-break: break-word; }}
          .button {{ display: inline-block; padding: 0.6rem 1rem; border: 1px solid #ccc; border-radius: 6px; text-decoration: none; color: inherit; margin-right: 0.5rem; margin-bottom: 0.5rem; }}
        </style>
      </head>
      <body>
        {body}
      </body>
    </html>
    """
    return HTMLResponse(page, status_code=status_code)


@app.get("/healthz")
def healthz() -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "app": APP_NAME,
            "consumer_count": len(LTI_CONSUMERS),
            "launch_target": LTI_URL or "self",
        }
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    if not LTI_CONSUMERS:
        body = """
        <h1>LTI MVP</h1>
        <p class=\"err\"><strong>No LTI consumers configured.</strong></p>
        <p>Add <code>LTI_CONSUMER_KEY_1</code> and <code>LTI_SHARED_SECRET_1</code> to your <code>.env</code>, then restart the app.</p>
        <p><a class=\"button\" href=\"/healthz\">Health check</a></p>
        """
        return html_page("LTI MVP", body, status_code=500)

    sample_key = html.escape(FIRST_LTI_CONSUMER_KEY or "")
    target = html.escape(default_launch_target(request))
    target_label = "Configured external LTI target" if LTI_URL else "Self-test target"
    body = f"""
    <h1>LTI MVP</h1>
    <p>This app can act as a minimal <strong>LTI 1.1</strong> receiver and launcher for testing.</p>
    <ul>
      <li>POST launch receiver: <code>/lti/launch</code></li>
      <li>Configured consumer keys: <strong>{len(LTI_CONSUMERS)}</strong></li>
      <li>First consumer key: <code>{sample_key}</code></li>
      <li>{target_label}: <code>{target}</code></li>
    </ul>
    <p>
      <a class=\"button\" href=\"/self-test\">Run signed launch</a>
      <a class=\"button\" href=\"/healthz\">Health check</a>
    </p>
    <p class=\"muted\">Set <code>LTI_URL</code> to post the signed launch to Avery (or another tool). Leave it blank to post back to this app. <code>PUBLIC_BASE_URL</code> is only for this app's own inbound validation URL when it is the receiver.</p>
    """
    return html_page("LTI MVP", body)


@app.get("/lti/launch")
def launch_get() -> PlainTextResponse:
    return PlainTextResponse("Use POST for an LTI 1.1 launch.", status_code=405)


@app.get("/self-test", response_class=HTMLResponse)
def self_test(request: Request) -> HTMLResponse:
    if not FIRST_LTI_CONSUMER_KEY:
        return html_page(
            "Self-test unavailable",
            "<h1>Self-test unavailable</h1><p class=\"err\">No LTI consumers configured.</p>",
            status_code=500,
        )

    launch_url = default_launch_target(request)
    secret = LTI_CONSUMERS[FIRST_LTI_CONSUMER_KEY]["secret"]
    signed_fields = sign_lti_launch(
        url=launch_url,
        key=FIRST_LTI_CONSUMER_KEY,
        secret=secret,
        params={
            "lti_message_type": "basic-lti-launch-request",
            "lti_version": "LTI-1p0",
            "resource_link_id": "mvp-self-test",
            "resource_link_title": "LTI MVP Self Test",
            "user_id": "123",
            "roles": "Learner",
            "ext_user_username": "testuser",
            "lis_person_name_full": "Test User",
            "lis_person_contact_email_primary": "test.user@example.com",
            "context_id": "001",
            "context_label": "DEMO101",
            "context_title": "LTI Demo Course",
            "launch_presentation_locale": "ja",
            "tool_consumer_instance_guid": "lti-mvp-local",
            "tool_consumer_info_product_family_code": "lti-mvp-self-test",
        },
    )

    inputs = "\n".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}" />'
        for key, value in signed_fields.items()
    )

    heading = "Avery launch" if LTI_URL else "Self-test launch"
    note = (
        '<p class="muted">This will POST directly to the configured <code>LTI_URL</code>.</p>'
        if LTI_URL
        else ""
    )
    body = f"""
    <h1>{heading}</h1>
    <p>Posting a signed LTI launch to:</p>
    <p><code>{html.escape(launch_url)}</code></p>
    {note}
    <form id=\"ltiLaunchForm\" method=\"post\" action=\"{html.escape(launch_url)}\">
      {inputs}
      <noscript><button type=\"submit\">Submit launch</button></noscript>
    </form>
    <script>document.getElementById('ltiLaunchForm').submit();</script>
    """
    return html_page(heading, body)


@app.post("/lti/launch", response_class=HTMLResponse)
async def lti_launch(request: Request) -> HTMLResponse:
    form = await request.form()
    form_items = [(key, str(value)) for key, value in form.multi_items()]
    params = dict(form_items)

    consumer_key = params.get("oauth_consumer_key")
    if not consumer_key:
        return html_page(
            "LTI launch failed",
            "<h1 class=\"err\">LTI launch failed</h1><p>Missing <code>oauth_consumer_key</code>.</p>",
            status_code=400,
        )

    consumer = LTI_CONSUMERS.get(consumer_key)
    if not consumer:
        return html_page(
            "LTI launch failed",
            f"<h1 class=\"err\">LTI launch failed</h1><p>Unknown consumer key: <code>{html.escape(consumer_key)}</code>.</p>",
            status_code=401,
        )

    url_for_validation = external_request_url(request)
    is_valid, reason = validate_lti_launch(
        method=request.method,
        url=url_for_validation,
        form_items=form_items,
        consumer_secret=consumer["secret"],
        nonce_store=nonce_store,
        timestamp_skew_seconds=TIMESTAMP_SKEW_SECONDS,
    )

    if not is_valid:
        body = f"""
        <h1 class=\"err\">LTI launch failed</h1>
        <p><strong>Reason:</strong> {html.escape(reason)}</p>
        <p><strong>URL used for validation:</strong> <code>{html.escape(url_for_validation)}</code></p>
        <p class=\"muted\">If you're behind a reverse proxy or tunnel, set <code>PUBLIC_BASE_URL</code> so the signature is checked against the exact public URL the LMS uses.</p>
        """
        return html_page("LTI launch failed", body, status_code=401)

    interesting_fields = [
        "user_id",
        "roles",
        "ext_user_username",
        "lis_person_name_full",
        "lis_person_contact_email_primary",
        "context_id",
        "context_label",
        "context_title",
        "resource_link_id",
        "resource_link_title",
        "tool_consumer_instance_guid",
        "tool_consumer_info_product_family_code",
        "launch_presentation_locale",
        "custom_school",
        "custom_program",
    ]

    rows = []
    for field in interesting_fields:
        value = params.get(field, "")
        rows.append(
            f"<tr><th>{html.escape(field)}</th><td class=\"wrap\">{html.escape(value)}</td></tr>"
        )

    pretty_payload = html.escape(json.dumps(params, indent=2, sort_keys=True))
    body = f"""
    <h1 class=\"ok\">LTI launch OK</h1>
    <p>The OAuth signature validated successfully.</p>
    <p><strong>Consumer key:</strong> <code>{html.escape(consumer_key)}</code></p>
    <p><strong>URL used for validation:</strong> <code>{html.escape(url_for_validation)}</code></p>
    <h2>Selected launch fields</h2>
    <table>{''.join(rows)}</table>
    <h2>Raw launch payload</h2>
    <pre>{pretty_payload}</pre>
    """
    return html_page("LTI launch OK", body)
