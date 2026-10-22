"""Search Console + GA4 collector. sync.py runs it with the Python from settings.json → google.python
(a venv with `google-auth` and `requests`):

    <venv>/bin/python collectors/gsc_ga4.py < request.json

Reads {"sites": [{"domain", "gsc", "ga4"}], "days": 90, "service_account_json": path, "ga4_properties": path}
on stdin and prints one JSON object keyed by domain. Read-only scopes. The service account must be added as a user
of each Search Console property and each GA4 property (Viewer is enough).
"""
import datetime as dt
import json
import os
import sys
from urllib.parse import quote

from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import service_account

SCOPES = ["https://www.googleapis.com/auth/webmasters.readonly",
          "https://www.googleapis.com/auth/analytics.readonly"]
GSC = "https://searchconsole.googleapis.com/webmasters/v3/sites/"
GA = "https://analyticsdata.googleapis.com/v1beta/"


def err(r):
    try:
        return r.json().get("error", {}).get("message") or f"HTTP {r.status_code}"
    except Exception:
        return f"HTTP {r.status_code}"


def gsc_query(s, site, body):
    r = s.post(GSC + quote(site, safe="") + "/searchAnalytics/query", json=body, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(err(r))
    return r.json().get("rows", [])


def gsc(s, site, days):
    end = dt.date.today() - dt.timedelta(days=1)
    start = end - dt.timedelta(days=days)
    daily = [[row["keys"][0], row["clicks"], row["impressions"], row["ctr"], row["position"]]
             for row in gsc_query(s, site, {"startDate": str(start), "endDate": str(end),
                                            "dimensions": ["date"], "rowLimit": 1000})]
    out = {"daily": daily}
    last = daily[-1][0] if daily else str(end)
    l_end = dt.date.fromisoformat(last)
    l_start = l_end - dt.timedelta(days=27)
    rng = {"startDate": str(l_start), "endDate": str(l_end)}
    out["window"] = [str(l_start), str(l_end)]
    out["top_queries"] = [[r["keys"][0], r["clicks"], r["impressions"], r["position"]]
                          for r in gsc_query(s, site, {**rng, "dimensions": ["query"], "rowLimit": 10})]
    out["top_pages"] = [[r["keys"][0], r["clicks"], r["impressions"]]
                        for r in gsc_query(s, site, {**rng, "dimensions": ["page"], "rowLimit": 5})]
    r = s.get(GSC + quote(site, safe="") + "/sitemaps", timeout=30)
    out["sitemaps"] = [{"path": m.get("path"), "errors": int(m.get("errors") or 0),
                        "warnings": int(m.get("warnings") or 0),
                        "last_downloaded": m.get("lastDownloaded"),
                        "pending": bool(m.get("isPending"))}
                       for m in (r.json().get("sitemap", []) if r.status_code == 200 else [])]
    return out


def ga4(s, prop, days):
    r = s.post(GA + prop + ":runReport", timeout=30, json={
        "dateRanges": [{"startDate": f"{days}daysAgo", "endDate": "yesterday"}],
        "dimensions": [{"name": "date"}],
        "metrics": [{"name": "activeUsers"}, {"name": "sessions"}, {"name": "screenPageViews"}],
        "orderBys": [{"dimension": {"dimensionName": "date"}}], "limit": 1000})
    if r.status_code != 200:
        raise RuntimeError(err(r))
    daily = []
    for row in r.json().get("rows", []):
        d = row["dimensionValues"][0]["value"]
        daily.append([f"{d[:4]}-{d[4:6]}-{d[6:]}"] + [float(m["value"]) for m in row["metricValues"]])
    out = {"daily": daily}
    r = s.post(GA + prop + ":runReport", timeout=30, json={
        "dateRanges": [{"startDate": "28daysAgo", "endDate": "yesterday"}],
        "dimensions": [{"name": "sessionDefaultChannelGroup"}],
        "metrics": [{"name": "sessions"}],
        "orderBys": [{"metric": {"metricName": "sessions"}, "desc": True}], "limit": 6})
    out["channels"] = [[row["dimensionValues"][0]["value"], float(row["metricValues"][0]["value"])]
                       for row in (r.json().get("rows", []) if r.status_code == 200 else [])]
    r = s.post(GA + prop + ":runRealtimeReport", timeout=30, json={"metrics": [{"name": "activeUsers"}]})
    rows = r.json().get("rows", []) if r.status_code == 200 else []
    out["realtime_users"] = int(rows[0]["metricValues"][0]["value"]) if rows else 0
    return out


def main():
    req = json.load(sys.stdin)
    days = int(req.get("days", 90))
    key = os.path.expanduser(req["service_account_json"])
    s = AuthorizedSession(service_account.Credentials.from_service_account_file(key, scopes=SCOPES))
    pf = req.get("ga4_properties") or ""
    props = json.load(open(pf)) if pf and os.path.exists(pf) else {}
    result = {}
    for site in req["sites"]:
        entry = {}
        if site.get("gsc"):
            try:
                entry["gsc"] = gsc(s, site["gsc"], days)
            except Exception as e:
                entry["gsc"] = {"error": str(e)[:300]}
        if site.get("ga4"):
            prop = site["ga4"] if str(site["ga4"]).startswith("properties/") else props.get(site["ga4"], {}).get("property")
            if not prop:
                entry["ga4"] = {"error": f"no GA4 property for '{site['ga4']}' (use 'properties/<id>' in sites.json or ga4-properties.json)"}
            else:
                try:
                    entry["ga4"] = ga4(s, prop, days)
                except Exception as e:
                    entry["ga4"] = {"error": str(e)[:300]}
        result[site["domain"]] = entry
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
