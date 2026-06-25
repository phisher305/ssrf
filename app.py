import os
import random
import string
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, request


app = Flask(__name__)

KNOWN_CONFIG_ID = "48267363-7b6a-4213-b4e1-cbffb8e6c5cd"

CONFIGURATIONS = {
    KNOWN_CONFIG_ID: {
        "organization_id": "org-a",
        "provider_name": "Production SMS Gateway",
    }
}

TOKENS = {
    "token-org-a": "org-a",
    "token-org-b": "org-b",
}


def generate_otp() -> str:
    return "".join(random.choice(string.digits) for _ in range(6))


def token_org() -> str | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return TOKENS.get(auth.removeprefix("Bearer ").strip())


def render_template_value(value, phone_number: str, otp: str) -> str:
    if not isinstance(value, str):
        return str(value)

    rendered = value.replace("{{phone_number}}", phone_number)
    rendered = rendered.replace("{{otp}}", otp)
    return rendered


def build_outbound_request(payload: dict, otp: str) -> tuple[str, str, dict, str | None]:
    credentials = payload.get("credentials") or {}
    gateway_url = credentials.get("gateway_url")
    if not gateway_url:
        raise ValueError("credentials.gateway_url is required")

    method = (credentials.get("http_method") or "GET").upper()
    phone_number = payload.get("phone_number") or ""
    body_template = credentials.get("body_template") or {}

    message = body_template.get(
        "message",
        f"Document signing authentication code is: {otp}",
    )

    rendered_fields = {
        credentials.get("message_key") or "message": render_template_value(
            message,
            phone_number,
            otp,
        ),
        credentials.get("destination_key") or "phone_number": phone_number,
    }

    if method == "GET":
        separator = "&" if "?" in gateway_url else "?"
        outbound_url = f"{gateway_url}{separator}{urlencode(rendered_fields)}"
        return method, outbound_url, {}, None

    return method, gateway_url, {}, jsonify_safe(rendered_fields)


def jsonify_safe(value: dict) -> str:
    import json

    return json.dumps(value, separators=(",", ":"))


def send_custom_sms(method: str, outbound_url: str, headers: dict, body: str | None) -> requests.Response:
    return requests.request(
        method,
        outbound_url,
        headers=headers,
        data=body,
        timeout=4,
        allow_redirects=True,
    )


def authz_error(config_id: str):
    config = CONFIGURATIONS.get(config_id)
    if not config:
        return jsonify(
            {
                "message": "SMS gateway configuration was not found",
                "status_code": 404,
            }
        ), 404

    org_id = token_org()
    if org_id != config["organization_id"]:
        return jsonify(
            {
                "message": "You do not have permission to test this SMS gateway configuration",
                "status_code": 403,
            }
        ), 403

    return None


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/")
def index():
    return jsonify(
        {
            "service": "vulnerable SMS gateway test lab",
            "target_endpoint": f"/sms-gateway/configurations/{KNOWN_CONFIG_ID}/test",
            "internal_hint": os.environ.get("phisher", "http://phisher:9001/"),
        }
    )


@app.post("/sms-gateway/configurations/<config_id>/test")
def test_sms_gateway(config_id: str):
    payload = request.get_json(silent=True) or {}
    otp = generate_otp()

    try:
        method, outbound_url, headers, body = build_outbound_request(payload, otp)
    except ValueError as exc:
        return jsonify({"message": str(exc), "status_code": 400}), 400

    # Intentionally vulnerable flow:
    # The server performs the attacker-controlled outbound request before checking
    # whether config_id exists or belongs to the caller's organization.
    try:
        provider_response = send_custom_sms(method, outbound_url, headers, body)
    except requests.RequestException as exc:
        return jsonify(
            {
                "message": "Failed to send OTP",
                "status_code": 400,
                "detail": (
                    "Failed sending custom SMS, "
                    f"Reason: {exc.__class__.__name__}: {exc}. "
                    f"Outbound URL: {outbound_url}"
                ),
                "otp_leaked_for_lab": otp,
            }
        ), 400

    if provider_response.status_code >= 400:
        return jsonify(
            {
                "message": "Failed to send OTP",
                "status_code": 400,
                "detail": (
                    "Failed sending custom SMS, "
                    f"Reason: upstream returned HTTP {provider_response.status_code}. "
                    f"Outbound URL: {outbound_url}. "
                    f"Upstream body: {provider_response.text[:500]}"
                ),
                "otp_leaked_for_lab": otp,
            }
        ), 400

    late_authz_error = authz_error(config_id)
    if late_authz_error:
        return late_authz_error

    return jsonify(
        {
            "message": "OTP sent",
            "status_code": 200,
            "provider_status_code": provider_response.status_code,
            "provider_response_preview": provider_response.text[:500],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
