#!/usr/bin/env python3

import os
import json
import time
import requests
import statistics
from datetime import datetime, timezone, timedelta

# --------------------------------------------------------------
# Load environment variables
# --------------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except:
    pass

OPENAI_ENDPOINT = os.getenv("OPENAI_ENDPOINT")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")

# API URLs
RIPE_BASE = "https://stat.ripe.net/data"
CFR_BASE = "https://api.cloudflare.com/client/v4/radar"

# Settings
REQUEST_TIMEOUT = 15
RETRY_COUNT = 3
LOOKBACK_HOURS = 24
RECENT_WINDOW_MINUTES = 60

TARGET_ASNS = [
    9498,      # Tata Communications
    55836,     # Jio
    132203,    # ACT Fibernet
    9829,      # BSNL
    16509,     # AWS
]


# --------------------------------------------------------------
# Logging
# --------------------------------------------------------------
def log(msg):
    print(f"[{datetime.now(timezone.utc).isoformat()}] {msg}")


# --------------------------------------------------------------
# HTTP helper with retry
# --------------------------------------------------------------
def http_get(url, params=None):
    for attempt in range(RETRY_COUNT):
        try:
            r = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            return r.json()
        except Exception:
            if attempt == RETRY_COUNT - 1:
                raise
            time.sleep(1)


# --------------------------------------------------------------
# Slack table helper
# --------------------------------------------------------------
def build_table(rows, headers):
    col_width = [len(h) for h in headers]

    for row in rows:
        for i, c in enumerate(row):
            col_width[i] = max(col_width[i], len(str(c)))

    def fmt(row):
        return "│ " + " │ ".join(str(c).ljust(col_width[i]) for i, c in enumerate(row)) + " │"

    top = "┌" + "┬".join("─"*(w+2) for w in col_width) + "┐"
    mid = "├" + "┼".join("─"*(w+2) for w in col_width) + "┤"
    bot = "└" + "┴".join("─"*(w+2) for w in col_width) + "┘"

    table = [top, fmt(headers), mid] + [fmt(r) for r in rows] + [bot]

    return "```\n" + "\n".join(table) + "\n```"


def slack_post(text):
    if not SLACK_WEBHOOK:
        return
    try:
        requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        log(f"Slack error: {e}")


# --------------------------------------------------------------
# Severity
# --------------------------------------------------------------
def severity_emoji(outage):
    if outage in [True, "true", "yes"]:
        return "🟥"
    if outage in ["maybe", "unknown"]:
        return "🟧"
    return "🟩"


# --------------------------------------------------------------
# RIPEstat API
# --------------------------------------------------------------
def canonical_asn(asn):
    return f"AS{asn}"

def ripe_as_overview(asn):
    return http_get(f"{RIPE_BASE}/as-overview/data.json?resource=AS{asn}")

def ripe_update_activity(asn):
    return http_get(f"{RIPE_BASE}/bgp-update-activity/data.json",
                    {"resource": asn, "num_hours": LOOKBACK_HOURS})

def ripe_bgp_updates(asn, start, end):
    return http_get(f"{RIPE_BASE}/bgp-updates/data.json",
                    {"resource": asn, "starttime": start.isoformat(), "endtime": end.isoformat()})


def detect_ripe_spike(activity):
    samples = activity.get("data", {}).get("updates", [])
    if not samples:
        return False, "No RIPE samples"

    withdrawals = [s.get("withdrawals", 0) or 0 for s in samples]
    n = max(1, len(withdrawals)//5)

    baseline = statistics.median(withdrawals[:-n] or [0])
    recent = statistics.mean(withdrawals[-n:])
    maximum = max(withdrawals[-n:])

    if baseline == 0:
        if recent >= 5 or maximum >= 10:
            return True, f"High withdrawals spike {recent}"
    else:
        if recent >= baseline * 3:
            return True, f"Recent withdrawals {recent} > 3×baseline {baseline}"

    return False, f"No significant withdrawal spike (baseline={baseline}, recent={recent})"


# --------------------------------------------------------------
# Cloudflare Radar API
# --------------------------------------------------------------
def cf_as_overview(asn):
    return http_get(f"{CFR_BASE}/entities/as{asn}/summary")

def cf_as_reachability(asn):
    return http_get(f"{CFR_BASE}/bgp/routes", {"asn": asn})

def cf_as_traffic(asn, start, end):
    return http_get(
        f"{CFR_BASE}/entities/as{asn}/traffic/time_series",
        {"since": start.isoformat(), "until": end.isoformat(), "interval": "1h"}
    )


def detect_cf_outage(asn, overview, reachability, traffic):
    summary = overview.get("result", {})
    health = summary.get("as_health", {})
    score = health.get("score", 100)

    # prefix visibility
    prefixes = reachability.get("result", {}).get("routes", [])
    prefix_count = len(prefixes)

    # traffic anomaly
    values = [v.get("value", 0) for v in traffic.get("result", {}).get("series", [])]
    if len(values) > 6:
        baseline = statistics.median(values[:-3])
        recent = statistics.mean(values[-3:])
    else:
        baseline = 0
        recent = 0

    reason = []
    outage = False

    if score < 50:
        outage = True
        reason.append(f"Low health score {score}")

    if prefix_count < 5:
        outage = True
        reason.append(f"Low prefix visibility {prefix_count}")

    if baseline > 0 and recent < baseline * 0.3:
        outage = True
        reason.append(f"Traffic drop {recent} < 0.3×{baseline}")

    if not reason:
        return False, "No Cloudflare anomalies"

    return True, "; ".join(reason)


# --------------------------------------------------------------
# LLM HELPERS
# --------------------------------------------------------------
def call_llm(prompt):
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": "Analyze ISP outage signals"},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0,
        "max_tokens": 250
    }

    for attempt in range(RETRY_COUNT):
        try:
            r = requests.post(f"{OPENAI_ENDPOINT}/chat/completions",
                              json=body, headers=headers,
                              timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            if attempt == RETRY_COUNT-1:
                return f'{{"outage":"unknown","summary":"LLM failed: {e}"}}'
            time.sleep(2)


def parse_llm_json(text):
    try:
        import re
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            return json.loads(m.group(0))
    except:
        pass

    return {"outage": "unknown", "summary": text}


# --------------------------------------------------------------
# MAIN
# --------------------------------------------------------------
def main():
    log("Starting Unified RIPE + Cloudflare Radar Detector")

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=RECENT_WINDOW_MINUTES)

    results = []

    for asn in TARGET_ASNS:
        asn_label = canonical_asn(asn)
        log(f"Checking {asn_label} ...")

        # -------- ISP identity from Cloudflare (best metadata source) --------
        try:
            ripe_info = ripe_as_overview(asn).get("data", {})
            isp = ripe_info.get("holder", "Unknown ISP")
        except:
            isp = "Unknown ISP"

        full_name = f"{asn_label} ({isp})"

        # --------------------------------------------------------------------
        # RIPE analysis
        # --------------------------------------------------------------------
        try:
            ripe_activity = ripe_update_activity(asn_label)
            ripe_outage, ripe_reason = detect_ripe_spike(ripe_activity)
        except:
            ripe_outage = False
            ripe_reason = "RIPE data unavailable"

        # --------------------------------------------------------------------
        # Cloudflare analysis
        # --------------------------------------------------------------------
        try: cf_reach = cf_as_reachability(asn)
        except: cf_reach = {}

        try: cf_traffic = cf_as_traffic(asn, start, now)
        except: cf_traffic = {}

        try:
            cf_outage, cf_reason = detect_cf_outage(asn, cf_info, cf_reach, cf_traffic)
        except:
            cf_outage = False
            cf_reason = "Radar data unavailable"

        # --------------------------------------------------------------------
        # Final combined outage flag before LLM
        # --------------------------------------------------------------------
        combined_outage = ripe_outage or cf_outage

        # --------------------------------------------------------------------
        # Determine summary BEFORE LLM (user requirement)
        # --------------------------------------------------------------------
        if not combined_outage:
            # your requirement
            summary = f"No anomalies for {isp}"
            outage_flag = False
        else:
            # Ask the LLM
            prompt = f"""
Analyze outage signals for ISP {full_name}.

RIPE: {ripe_reason}
Cloudflare: {cf_reason}

Return JSON:
- outage: true/false/maybe
- summary: 2 sentences maximum
"""
            llm_resp = call_llm(prompt)
            result = parse_llm_json(llm_resp)
            outage_flag = result.get("outage", "unknown")
            summary = result.get("summary", f"Issues detected for {isp}")

        results.append({
            "isp": full_name,
            "outage": outage_flag,
            "summary": summary
        })

    # --------------------------------------------------------------
    # ALWAYS OUTPUT: Console + Slack
    # --------------------------------------------------------------
    rows = []
    for r in results:
        rows.append([
            severity_emoji(r["outage"]),
            r["isp"],
            r["outage"],
            r["summary"]
        ])

    headers = ["Severity", "ASN / ISP", "Outage?", "Summary"]

    table = build_table(rows, headers)

    print("\n=== Unified ISP Outage Detector Summary ===")
    print(table)

    slack_text = (
        "*🌐 Unified ISP Outage Detector (RIPE + Cloudflare)*\n"
        "_🟥 Critical | 🟧 Warning | 🟩 Normal_\n"
        f"{table}"
    )
    slack_post(slack_text)

    log("Slack notification sent.")
    log("Completed.")


if __name__ == "__main__":
    main()
