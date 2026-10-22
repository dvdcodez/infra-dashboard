"""App Store Connect collector. sync.py runs it with the Python from settings.json → appstore.python
(a venv with `PyJWT`, `cryptography` and `requests`):

    <venv>/bin/python collectors/asc.py < request.json

Reads {"apps": ["<apple id>", ...], "dates": ["YYYY-MM-DD", ...], "config": "<path to appstore.json>"} on stdin.
appstore.json: {"key_id": "...", "issuer_id": "...", "key_file": "~/.../AuthKey_XXXX.p8", "vendor_number": "..."}
(an App Store Connect API key with at least the Sales and Reports role; vendor number from Payments and Financial Reports).

Prints {"apps": {id: {name, bundle, versions}}, "days": {date: {"status", "units": {id: {...}}}}}.
Read-only: GET /v1/apps, /v1/apps/{id}/appStoreVersions, /v1/salesReports (daily SUMMARY).
"""
import csv
import gzip
import io
import json
import os
import sys
import time

import jwt
import requests

BASE = "https://api.appstoreconnect.apple.com"
# Sales report "Product Type Identifier" groups.
DOWNLOADS = {"1", "1F", "1T", "F1", "1E", "1EP", "1EU"}
REDOWNLOADS = {"3", "3F", "3T", "F3"}
UPDATES = {"7", "7F", "7T", "F7"}


class Client:
    def __init__(self, cfg):
        self.cfg = cfg
        self.key = open(os.path.expanduser(cfg["key_file"])).read()

    def token(self):
        now = int(time.time())
        return jwt.encode({"iss": self.cfg["issuer_id"], "iat": now, "exp": now + 900, "aud": "appstoreconnect-v1"},
                          self.key, algorithm="ES256", headers={"kid": self.cfg["key_id"]})

    def get(self, path, accept="application/json", params=None):
        return requests.get(BASE + path, params=params, timeout=60,
                            headers={"Authorization": "Bearer " + self.token(), "Accept": accept})


def versions(c, app_id):
    r = c.get(f"/v1/apps/{app_id}/appStoreVersions",
              params={"limit": 3, "fields[appStoreVersions]": "versionString,appStoreState,platform,createdDate"})
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}
    return [{"version": v["attributes"]["versionString"], "state": v["attributes"]["appStoreState"],
             "platform": v["attributes"]["platform"], "created": v["attributes"]["createdDate"]}
            for v in r.json().get("data", [])]


def day_report(c, day, sku_to_id):
    r = c.get("/v1/salesReports", accept="application/a-gzip", params={
        "filter[frequency]": "DAILY", "filter[reportType]": "SALES", "filter[reportSubType]": "SUMMARY",
        "filter[vendorNumber]": c.cfg["vendor_number"], "filter[reportDate]": day, "filter[version]": "1_0"})
    if r.status_code == 404:
        return {"status": "none", "units": {}}   # no sales that day, or not published yet
    if r.status_code != 200:
        return {"status": "error", "error": f"HTTP {r.status_code}", "units": {}}
    units = {}
    for row in csv.DictReader(io.StringIO(gzip.decompress(r.content).decode("utf-8")), delimiter="\t"):
        ptype = row.get("Product Type Identifier", "")
        app = row.get("Apple Identifier", "")
        if ptype.startswith("IA") or ptype.startswith("FI"):
            app = sku_to_id.get(row.get("Parent Identifier", ""), app)
        e = units.setdefault(app, {"downloads": 0, "redownloads": 0, "updates": 0, "iap": 0})
        n = int(float(row.get("Units") or 0))
        if ptype in DOWNLOADS:
            e["downloads"] += n
        elif ptype in REDOWNLOADS:
            e["redownloads"] += n
        elif ptype in UPDATES:
            e["updates"] += n
        elif ptype.startswith("IA") or ptype.startswith("FI"):
            e["iap"] += n
    return {"status": "ok", "units": units}


def main():
    req = json.load(sys.stdin)
    c = Client(json.load(open(os.path.expanduser(req["config"]))))
    out = {"apps": {}, "days": {}}
    r = c.get("/v1/apps", params={"fields[apps]": "name,bundleId,sku", "limit": 200})
    if r.status_code != 200:
        json.dump({"error": f"apps: HTTP {r.status_code}"}, sys.stdout)
        return
    sku_to_id = {}
    for a in r.json().get("data", []):
        sku_to_id[a["attributes"].get("sku", "")] = a["id"]
        if a["id"] in req["apps"]:
            out["apps"][a["id"]] = {"name": a["attributes"]["name"], "bundle": a["attributes"]["bundleId"],
                                    "versions": versions(c, a["id"])}
    for day in req.get("dates", []):
        try:
            out["days"][day] = day_report(c, day, sku_to_id)
        except Exception as e:
            out["days"][day] = {"status": "error", "error": str(e)[:200], "units": {}}
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
