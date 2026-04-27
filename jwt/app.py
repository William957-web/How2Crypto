import os
import time

from flask import Flask, render_template, request

import level1
import level2
import level3
import level4
from jwtlib import JWTError
from jwtlib import encode_token


APP_DIR = os.path.dirname(__file__)
app = Flask(__name__)

LEVELS = {
    "level1": {
        "title": "Level 1: none algorithm",
        "summary": "The server defaults to HS256, but it still accepts alg=none.",
        "module": level1,
    },
    "level2": {
        "title": "Level 2: weak HS256 secret",
        "summary": "The token is signed with HS256, but the secret is weak enough to brute force.",
        "module": level2,
    },
    "level3": {
        "title": "Level 3: user-controlled key file",
        "summary": "The server reads the HMAC secret from the key file named in the JWT header.",
        "module": level3,
    },
    "level4": {
        "title": "Level 4: HS256/RS256 confusion",
        "summary": "The verifier accepts both HS256 and RS256 and reads the shared secret from a PEM file.",
        "module": level4,
    },
}


def build_token_data(user):
    return {
        "user": user,
        "timestamp": int(time.time()),
    }


def issue_guest_token(level_name):
    module = LEVELS[level_name]["module"]
    payload = build_token_data("guest")

    if hasattr(module, "PRIVATE_KEY_FILE"):
        return encode_token(payload, module.PRIVATE_KEY_FILE, alg="RS256")

    if hasattr(module, "DEFAULT_KEYFILE"):
        return encode_token(
            payload,
            module.read_secret(module.DEFAULT_KEYFILE),
            alg="HS256",
            headers={"kid": module.DEFAULT_KEYFILE},
        )

    return encode_token(payload, module.SECRET, alg="HS256")


def build_level_context(level_name):
    config = LEVELS[level_name]
    module = config["module"]
    context = {
        "name": level_name,
        "title": config["title"],
        "summary": config["summary"],
        "guest_token": issue_guest_token(level_name),
        "source_code": module.source_for_display(),
        "submitted_token": "",
        "result": None,
        "flag": None,
        "error": None,
    }
    return context


@app.route("/")
def index():
    return render_template("index.html", levels=LEVELS)


@app.route("/<level_name>", methods=["GET", "POST"])
def level_page(level_name):
    if level_name not in LEVELS:
        return ("not found", 404)

    context = build_level_context(level_name)
    module = LEVELS[level_name]["module"]

    if request.method == "POST":
        submitted_token = request.form.get("token", "").strip()
        context["submitted_token"] = submitted_token

        if not submitted_token:
            context["error"] = "Token is required."
            return render_template("level.html", **context)

        try:
            payload = module.verify(submitted_token)
            user = payload.get("user")
            context["result"] = f"Token accepted. user={user!r}"
            if user == "whale":
                context["flag"] = module.FLAG
            else:
                context["error"] = "You are authenticated, but you are not whale."
        except (JWTError, OSError, ValueError) as exc:
            context["error"] = str(exc)

    return render_template("level.html", **context)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
