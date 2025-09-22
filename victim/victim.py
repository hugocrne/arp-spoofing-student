import datetime
import json
import os
import time

import requests

SERVER_URL = os.environ.get("SERVER_URL", "http://arp_server/")
CLIENT_ID = os.environ.get("CLIENT_ID", "victim")
REQUEST_INTERVAL = float(os.environ.get("REQUEST_INTERVAL", "4"))


def log(message: str) -> None:
    timestamp = datetime.datetime.utcnow().isoformat(timespec="seconds")
    print(f"[VICTIM {timestamp}Z] {message}", flush=True)


if __name__ == "__main__":
    log(f"starting traffic generator towards {SERVER_URL}")
    counter = 1
    while True:
        payload = {
            "client": CLIENT_ID,
            "sequence": counter,
            "ts": datetime.datetime.utcnow().isoformat(timespec="seconds"),
        }
        try:
            response = requests.post(
                SERVER_URL,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=3,
            )
            log(
                f"POST seq={counter} status={response.status_code} response={response.text.strip()}"
            )
        except Exception as exc:  # noqa: BLE001
            log(f"request failed: {exc}")
        counter += 1
        time.sleep(REQUEST_INTERVAL)
