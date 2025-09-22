import datetime
import sys

from flask import Flask, request

app = Flask(__name__)


def log(msg: str) -> None:
    timestamp = datetime.datetime.utcnow().isoformat(timespec="seconds")
    print(f"[SERVER {timestamp}Z] {msg}", flush=True)


@app.route("/", methods=["GET", "POST"])
def index():
    body = request.get_data(as_text=True) or "<empty body>"
    log(
        "message from %s user-agent=%s body=%s"
        % (request.remote_addr, request.user_agent.string, body)
    )
    return {"status": "ok", "echo": body}, 200


if __name__ == "__main__":
    log("HTTP server starting on port 80")
    app.run(host="0.0.0.0", port=80, debug=False)
