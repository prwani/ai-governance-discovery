"""Compare exact deployment identities with Microsoft's public retirement schedule.

Only factual metadata for matched rows is retained, not the downloaded article.
Dates describe the published schedule, not whether an inference API still works.
"""

import json
import re
from datetime import date, datetime, timezone
from html import unescape
from html.parser import HTMLParser
from http.client import HTTPException
from urllib.request import HTTPRedirectHandler, Request, build_opener


SOURCE_URL = (
    "https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/"
    "model-retirement-schedule"
)
DOWNLOAD_TIMEOUT = 20
MAX_SOURCE_BYTES = 4 * 1024 * 1024


def _normalize(value):
    return " ".join(str(value or "").split()).casefold()


def _publisher(value):
    value = _normalize(value)
    return {
        "azure openai": "openai",
        "mistral ai": "mistralai",
        "black forest labs": "blackforestlabs",
        "stability ai": "stabilityai",
        "ntt data": "nttdata",
    }.get(value, value)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Retirement source redirected; authoritative URL must be reviewed")


def download_schedule():
    """Fetch only the fixed public URL, without ARM credentials or redirects."""
    request = Request(SOURCE_URL, headers={
        "Accept": "text/html, text/markdown, text/plain",
        "User-Agent": "ai-governance-discovery/1.0",
    })
    with build_opener(_NoRedirect()).open(request, timeout=DOWNLOAD_TIMEOUT) as response:
        content = response.read(MAX_SOURCE_BYTES + 1)
        if len(content) > MAX_SOURCE_BYTES:
            raise ValueError("Retirement source exceeded size limit")
        return content.decode("utf-8-sig")


class _ScheduleHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.headings = {}
        self.titles = []
        self.tables = []
        self.capture = None
        self.text = []
        self.table = None
        self.row = None

    def handle_starttag(self, tag, attrs):
        if re.fullmatch(r"h[1-6]", tag) or tag == "title":
            self.capture, self.text = tag, []
        elif tag == "table":
            self.table = (list(self.headings.values()), [])
        elif tag == "tr" and self.table is not None:
            self.row = []
        elif tag in ("td", "th") and self.row is not None:
            self.capture, self.text = tag, []
        elif tag == "br" and self.capture:
            self.text.append(" ")

    def handle_data(self, data):
        if self.capture:
            self.text.append(data)

    def handle_endtag(self, tag):
        if tag == self.capture:
            text = " ".join("".join(self.text).split())
            if tag == "title":
                self.titles.append(text)
            elif tag.startswith("h"):
                level = int(tag[1])
                self.headings = {k: v for k, v in self.headings.items() if k < level}
                self.headings[level] = text
                if level == 1:
                    self.titles.append(text)
            else:
                self.row.append(text)
            self.capture = None
        elif tag == "tr" and self.table is not None and self.row is not None:
            if self.row:
                self.table[1].append(self.row)
            self.row = None
        elif tag == "table" and self.table is not None:
            self.tables.append(self.table)
            self.table = None


def _markdown_tables(source):
    headings, titles, tables = {}, [], []
    rows = None
    for line in source.splitlines():
        heading = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if heading:
            level, text = len(heading[1]), heading[2]
            headings = {k: v for k, v in headings.items() if k < level}
            headings[level] = text
            if level == 1:
                titles.append(text)
            rows = None
        elif line.strip().startswith("|"):
            if rows is None:
                rows = []
                tables.append((list(headings.values()), rows))
            cells = [unescape(re.sub(r"[`*]", "", cell.strip()))
                     for cell in line.strip().strip("|").split("|")]
            if not all(re.fullmatch(r":?-+:?", cell) for cell in cells):
                rows.append(cells)
        else:
            rows = None
    return titles, tables


def _retirement_date(value):
    if _normalize(value) in (
        "", "-", "—", "–", "tbd", "n/a", "not announced", "not yet announced",
        "not scheduled", "no date published",
    ):
        return ""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Unrecognized retirement date in schedule")
    return date.fromisoformat(value).isoformat()


def parse_schedule(source):
    """Parse HTML or Markdown into exact model/version facts.

    Fine-tuned deployment dates are separate from base and training dates.
    Schema/title changes fail explicitly rather than returning an empty schedule.
    """
    if re.search(r"<(?:html|table|h1)\b", source, re.I):
        parser = _ScheduleHTML()
        parser.feed(source)
        parser.close()
        titles, tables = parser.titles, parser.tables
    else:
        titles, tables = _markdown_tables(source)
    if not any("model retirement schedule" in _normalize(title) for title in titles):
        raise ValueError("Retirement schedule title was not recognized")
    entries = []
    for headings, rows in tables:
        if not rows:
            continue
        headers = [_normalize(cell) for cell in rows[0]]
        if "model" not in headers or "version" not in headers:
            continue
        fine_tuned = "deployment retirement date" in headers
        required = ({"model", "version", "training retirement date", "deployment retirement date"}
                    if fine_tuned else
                    {"model", "version", "lifecycle", "retirement date", "replacement"})
        if not required.issubset(headers):
            raise ValueError("Retirement schedule table columns changed")
        publishers = [heading for heading in headings
                      if _normalize(heading) not in ("fine-tuned models", "fine tuned models")]
        publisher = publishers[-1] if publishers else ""
        if not publisher or "retirement schedule" in _normalize(publisher):
            raise ValueError("Retirement table publisher heading was not recognized")
        for cells in rows[1:]:
            if len(cells) != len(headers):
                raise ValueError("Retirement schedule table row has unexpected columns")
            fact = dict(zip(headers, cells))
            if not fact["model"] or not fact["version"]:
                raise ValueError("Retirement schedule model identity is empty")
            entry = {
                "model_name": fact["model"], "model_version": fact["version"],
                "publisher": publisher,
                "lifecycle": fact.get("lifecycle", ""),
                "retirement_date": _retirement_date(
                    fact["deployment retirement date"] if fine_tuned else fact["retirement date"]),
                "replacement": fact.get("replacement", ""),
                "schedule_kind": "fine_tuned_deployment" if fine_tuned else "base",
            }
            if fine_tuned:
                entry["training_retirement_date"] = fact["training retirement date"]
            entries.append(entry)
    if not entries:
        raise ValueError("No retirement schedule rows were recognized")
    return entries


def collect_retirements(client, deployments: list[dict], now: datetime = None,
                        warning_days: int = 90) -> list[dict]:
    """Return one evidence-bearing row per deployment, including unknown matches.

    ``now`` uses UTC (naive datetimes are interpreted as UTC). The inclusive
    warning window is calendar days 0..warning_days. ``is_fine_tuned=True`` or
    ``fine_tuned=True`` selects only the fine-tuned deployment table; custom
    model names are never stripped or guessed back to their base models.
    """
    if not isinstance(warning_days, int) or isinstance(warning_days, bool) or warning_days < 0:
        raise ValueError("warning_days must be a nonnegative integer")
    now = now or datetime.now(timezone.utc)
    today = now.replace(tzinfo=timezone.utc).date() if now.tzinfo is None else now.astimezone(
        timezone.utc).date()
    entries, retrieved, failure = [], "", ""
    try:
        source = download_schedule()
        retrieved = datetime.now(timezone.utc).isoformat()
    except (OSError, ValueError, HTTPException) as exc:
        failure = "Schedule download failed (" + type(exc).__name__ + "); status is unknown."
        client.error(SOURCE_URL, "download_retirement_schedule", failure)
    if not failure:
        try:
            entries = parse_schedule(source)
        except ValueError as exc:
            failure = "Schedule parsing failed: " + str(exc) + "; status is unknown."
            client.error(SOURCE_URL, "parse_retirement_schedule", failure)
    results = []
    for deployment in deployments:
        row = {key: deployment.get(key, "") for key in (
            "id", "name", "resource_id", "account_id", "resource_group",
            "subscription_id", "subscription_name", "tenant_id", "location",
            "model_name", "model_version", "model_format", "model_publisher",
        )}
        row.update({
            "deployment_id": deployment.get("id", ""),
            "deployment_name": deployment.get("name", ""),
            "lifecycle": "", "publisher": "", "retirement_date": "", "replacement": "",
            "days_to_retirement": "", "retirement_status": "schedule_unavailable",
            "source_url": SOURCE_URL, "schedule_retrieved_at": retrieved,
            "warning_days": warning_days, "notes": failure, "match_evidence": "[]",
        })
        if failure:
            results.append(row)
            continue
        fine_tuned = (deployment.get("is_fine_tuned") is True
                      or deployment.get("fine_tuned") is True)
        kind = "fine_tuned_deployment" if fine_tuned else "base"
        publisher = _publisher(deployment.get("model_publisher"))
        if publisher in ("", "aiservices", "azure ai", "azure"):
            publisher = _publisher(deployment.get("model_format"))
            if publisher in ("aiservices", "azure ai", "azure"):
                publisher = ""
        named = [entry for entry in entries
                 if _normalize(entry["model_name"]) == _normalize(row["model_name"])
                 and entry["schedule_kind"] == kind
                 and (not publisher or _publisher(entry["publisher"]) == publisher)]
        matches = [entry for entry in named
                   if _normalize(entry["model_version"]) == _normalize(row["model_version"])
                   and _normalize(row["model_version"])]
        row["retirement_status"] = "version_not_listed" if named else "not_listed"
        row["notes"] = "No exact model, version and publisher match; no dates inferred."
        row["match_evidence"] = json.dumps(matches, ensure_ascii=False, sort_keys=True)
        if matches:
            facts = {(_publisher(entry["publisher"]), _normalize(entry["lifecycle"]),
                      entry["retirement_date"], _normalize(entry["replacement"])) for entry in matches}
            if len(facts) > 1:
                row["retirement_status"] = "ambiguous"
                row["notes"] = "Conflicting exact schedule entries; no retirement date selected."
            else:
                match = matches[0]
                row.update({key: match[key] for key in
                            ("publisher", "lifecycle", "retirement_date", "replacement")})
                row["notes"] = ("Exact model/version match in " + kind + " schedule. "
                                "Published dates do not prove current API availability.")
                if not publisher:
                    row["notes"] += " Deployment publisher unavailable."
                if match["retirement_date"]:
                    days = (date.fromisoformat(match["retirement_date"]) - today).days
                    row["days_to_retirement"] = days
                    row["retirement_status"] = (
                        "past_retirement_date" if days < 0 else
                        "retiring_soon" if days <= warning_days else "scheduled")
                else:
                    row["retirement_status"] = "no_date_published"
        results.append(row)
    return results
