#!/usr/bin/env python3
import sys
import json
import logging
import requests
from datetime import datetime

LOG_FILE = "/var/ossec/logs/integrations.log"
USER_AGENT = "Wazuh-Gemini-Teams/1.0"

# CHANGE THIS to your Wazuh Dashboard IP or DNS (e.g. https://wazuh.example.com)
DASHBOARD_BASE = "https://192.168.30.2"

INDEX_PATTERN = "wazuh-alerts-*"
TIME_FROM = "now-90d"
TIME_TO = "now"


def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
    )
    return logging.getLogger("custom-gemini-teams")


def parse_args(argv):
    alert_file = None
    webhook = None
    level = None
    for arg in argv[1:]:
        if arg.startswith("/tmp/") and arg.endswith(".alert"):
            alert_file = arg
        elif arg.startswith("http://") or arg.startswith("https://"):
            webhook = arg
        else:
            try:
                level = int(arg)
            except Exception:
                pass
    return alert_file, webhook, level


def load_alert(path):
    with open(path, "r") as f:
        return json.load(f)


def get_nested(dct, path, default=None):
    cur = dct
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def format_time(ts):
    if not ts:
        return "N/A"
    try:
        if len(ts) > 5 and ts[-5] in ["+", "-"] and ts[-2:].isdigit():
            ts = ts[:-2] + ":" + ts[-2:]
        return datetime.fromisoformat(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


def priority(level_int):
    if level_int >= 12:
        return "CRITICAL", "Attention"
    if level_int >= 7:
        return "HIGH", "Warning"
    if level_int >= 4:
        return "MEDIUM", "Good"
    return "LOW", "Accent"


def rison_escape(value):
    return str(value).replace("'", "''").strip()


def build_filter_a(alert_id):
    return (
        "(filters:!(("
        "'$state':(store:appState),"
        "meta:("
        "alias:!n,"
        "disabled:!f,"
        f"index:'{INDEX_PATTERN}',"
        "key:id,"
        "negate:!f,"
        f"params:(query:'{alert_id}'),"
        "type:phrase"
        "),"
        f"query:(match_phrase:(id:'{alert_id}'))"
        ")),"
        "query:(language:kuery,query:''))"
    )


def build_g():
    return f"(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:{TIME_FROM},to:{TIME_TO}))"


def build_dashboard_url(original_alert):
    original_id = rison_escape(original_alert.get("id", ""))
    if not original_id:
        return (
            f"{DASHBOARD_BASE}/app/threat-hunting#/overview/?tab=general&tabView=events"
            f"&_a=(filters:!(),query:(language:kuery,query:''))"
            f"&_g={build_g()}"
        )

    return (
        f"{DASHBOARD_BASE}/app/threat-hunting#/overview/?tab=general&tabView=events"
        f"&(_a={build_filter_a(original_id)})"
        f"&(_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now)))"
        f"&_a={build_filter_a(original_id)}"
        f"&_g={build_g()}"
    )


def extract_original_alert(enriched_alert):
    original = get_nested(enriched_alert, ["data", "gemini", "source", "original_alert"])
    if isinstance(original, dict) and original:
        return original
    return enriched_alert


def extract_gemini_summary(enriched_alert):
    s = get_nested(enriched_alert, ["data", "gemini", "summary"])
    if isinstance(s, str) and s.strip():
        return s.strip()
    return ""


def extract_vt_permalink(enriched_alert):
    vt1 = get_nested(enriched_alert, ["data", "virustotal", "permalink"])
    if isinstance(vt1, str) and vt1.startswith("http"):
        return vt1

    vt2 = get_nested(enriched_alert, ["data", "gemini", "source", "virustotal_permalink"])
    if isinstance(vt2, str) and vt2.startswith("http"):
        return vt2

    vt3 = get_nested(enriched_alert, ["data", "gemini", "source", "original_alert", "data", "virustotal", "permalink"])
    if isinstance(vt3, str) and vt3.startswith("http"):
        return vt3

    return ""


def to_pairs(facts):
    left = []
    right = []
    for i, (k, v) in enumerate(facts):
        block = {
            "type": "TextBlock",
            "text": f"**{k}**  \n{v}",
            "wrap": True,
            "spacing": "Small",
        }
        if i % 2 == 0:
            left.append(block)
        else:
            right.append(block)
    return left, right


def make_payload(enriched_alert):
    original = extract_original_alert(enriched_alert)
    summary = extract_gemini_summary(enriched_alert)
    vt_link = extract_vt_permalink(enriched_alert)

    rule = original.get("rule", {}) or {}
    agent = original.get("agent", {}) or {}

    try:
        level_int = int(rule.get("level", 0))
    except Exception:
        level_int = 0

    pr_txt, pr_color = priority(level_int)

    groups = ", ".join(rule.get("groups", []) or []) or "N/A"
    agent_val = f"{agent.get('name','manager')} ({agent.get('ip','N/A')})"

    facts_list = [
        ("Level", f"{pr_txt} ({level_int})"),
        ("Rule ID", str(rule.get("id", "N/A"))),
        ("Description", str(rule.get("description", "N/A"))),
        ("Groups", groups),
        ("Agent", agent_val),
        ("Timestamp", format_time(original.get("timestamp"))),
        ("Alert ID", str(original.get("id", "N/A"))),
    ]
    if vt_link:
        facts_list.append(("VirusTotal", vt_link))

    left_col, right_col = to_pairs(facts_list)

    if not summary:
        summary = "(No se encontró el campo data.gemini.summary en la alerta enriquecida.)"
    if len(summary) > 6500:
        summary = summary[:6500] + "…"

    dashboard_url = build_dashboard_url(original)

    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": [
            {
                "type": "TextBlock",
                "text": f"{pr_txt} WAZUH ALERT (GEMINI)",
                "weight": "Bolder",
                "size": "Large",
                "color": pr_color,
            },
            {
                "type": "ColumnSet",
                "columns": [
                    {"type": "Column", "width": "stretch", "items": left_col},
                    {"type": "Column", "width": "stretch", "items": right_col},
                ],
                "spacing": "Medium",
            },
            {"type": "TextBlock", "text": "Gemini enrichment", "weight": "Bolder", "spacing": "Medium"},
            {"type": "TextBlock", "text": summary, "wrap": True, "fontType": "Monospace", "spacing": "Small"},
        ],
        "actions": [{"type": "Action.OpenUrl", "title": "Dashboard", "url": dashboard_url}],
    }

    if vt_link:
        card["actions"].append({"type": "Action.OpenUrl", "title": "VirusTotal", "url": vt_link})

    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def send(webhook_url, payload, logger):
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    try:
        r = requests.post(webhook_url, json=payload, headers=headers, timeout=30)
        if r.status_code in (200, 202):
            logger.info(f"custom-gemini-teams: Sent ok (status {r.status_code})")
            return True
        logger.error(f"custom-gemini-teams: Send failed: {r.status_code} {r.text}")
        return False
    except Exception as e:
        logger.error(f"custom-gemini-teams: Exception: {e}")
        return False


def main():
    logger = setup_logger()
    alert_file, webhook, min_level = parse_args(sys.argv)
    if not alert_file or not webhook:
        sys.exit(1)

    try:
        alert = load_alert(alert_file)
    except Exception as e:
        logger.error(f"custom-gemini-teams: Cannot load alert: {e}")
        sys.exit(1)

    try:
        lvl = int((alert.get("rule", {}) or {}).get("level", 0))
    except Exception:
        lvl = 0

    if min_level is not None and lvl < int(min_level):
        sys.exit(0)

    payload = make_payload(alert)
    sys.exit(0 if send(webhook, payload, logger) else 1)


if __name__ == "__main__":
    main()
