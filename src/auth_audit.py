"""Per-reseller, read-only DNS authentication audit.

DNS presence is not evidence of DKIM signing, real SMTP SPF pass, DMARC
alignment, or inbox delivery. Never mutate DNS, Exim, or reseller policies.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from datetime import datetime, timezone

from dns_inspector import DNSError, lookup, public_dns_domain, suggested_spf, lookup_cost

SELECTOR_RE = re.compile(r"^[a-z0-9_-]{1,63}$", re.I)
TAGS_RE = re.compile(r"(?:^|;)\s*([a-zA-Z]+)\s*=\s*([^;]*)")


def _tags(value):
    return {key.lower(): val.strip() for key, val in TAGS_RE.findall(value)}


def _proposal(action, name, value, note):
    return {"action": action, "type": "TXT", "name": name, "value": value, "note": note}


def _ip_check(record, ip):
    """A conservative explicit-ip4/ip6 mechanism check; not an SPF evaluator."""
    addr = ipaddress.ip_address(ip)
    earlier_negative_dns = False
    for token in record.split()[1:]:
        qualifier = token[0] if token[:1] in "+-~?" else "+"
        mechanism = token[1:] if token[:1] in "+-~?" else token
        low = mechanism.lower()
        if low == "all":
            return ("needs_action", "An all mechanism precedes an explicit permit for this IP.")
        if low.startswith(("ip4:", "ip6:")):
            try:
                network = ipaddress.ip_network(mechanism.split(":", 1)[1], strict=False)
                if addr in network:
                    if qualifier == "+":
                        if earlier_negative_dns:
                            return ("review", "A preceding negative DNS-based mechanism may match before this permit.")
                        return ("verified_dns", "The public SPF TXT explicitly permits this IP before all; this is not a live SPF test.")
                    return ("needs_action", "An earlier SPF IP mechanism matches with a non-pass qualifier.")
            except ValueError:
                return ("review", "Malformed IP mechanism; manual SPF review required.")
        if qualifier in ("-", "~", "?") and low.startswith(("a", "mx", "include:", "exists:", "ptr")):
            earlier_negative_dns = True
    return ("needs_action", "No explicit passing IP mechanism was found; a/mx/include may still authorize this IP.")


def audit_domain(domain, outbound_ip="", selector="default", expected_challenge=None,
                 resolver=None):
    """Return documented, conservative status and DNS-only proposals.

    outbound_ip MUST be a confirmed public SMTP egress address, supplied by the
    WHM administrator. No server hostname or interface guesses are made.
    expected_challenge is a saved RSM token and is never included in the result.
    """
    if not public_dns_domain(domain):
        raise DNSError("Invalid public sender domain")
    if not isinstance(selector, str) or not SELECTOR_RE.fullmatch(selector):
        raise DNSError("Invalid DKIM selector")
    if outbound_ip:
        try:
            address = ipaddress.ip_address(outbound_ip)
        except ValueError as exc:
            raise DNSError("Invalid SMTP egress IP") from exc
        if not address.is_global:
            raise DNSError("SMTP egress IP must be globally routable")
        outbound_ip = str(address)

    query = resolver if resolver is not None else lookup
    results = {
        "domain": domain, "outbound_ip": outbound_ip, "selector": selector.lower(),
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ownership": {"status": "not_checked", "name": "_rsm." + domain,
                      "message": "No RSM ownership challenge configured"},
        "spf": {"status": "not_checked", "records": [], "proposal": None, "message": ""},
        "dkim": {"status": "not_checked", "name": selector.lower() + "._domainkey." + domain,
                 "records": [], "proposal": None, "message": "",
                 "signing": "not_verified"},
        "dmarc": {"status": "not_checked", "name": "_dmarc." + domain,
                  "records": [], "proposal": None, "message": ""},
        "notes": [
            "Published DNS records do not prove message authentication or inbox delivery.",
            "DKIM requires a matching private signing key and a DKIM-Signature on a real message.",
        ],
    }
    own = results["ownership"]
    if expected_challenge:
        vals = query(own["name"], "TXT")
        if expected_challenge in vals:
            own.update(status="verified_dns", message="Published ownership challenge matches the saved token.")
        else:
            own.update(status="needs_action", message="Ownership TXT missing or does not match; re-verify ownership.")

    spf = results["spf"]
    spf["records"] = [r for r in query(domain, "TXT") if r.lower().startswith("v=spf1")
                      and (len(r) == 6 or r[6].isspace())]
    if len(spf["records"]) > 1:
        spf.update(status="needs_action", message="Multiple SPF records cause PermError. Merge manually into one TXT.")
    elif not spf["records"]:
        spf.update(status="needs_action", message="No SPF policy found. Inventory ALL legitimate senders before creating one.")
        if outbound_ip:
            part = ("ip4:" if ":" not in outbound_ip else "ip6:") + outbound_ip
            spf["proposal"] = _proposal(
                "create_after_review", domain, "v=spf1 " + part + " ~all",
                "EXAMPLE ONLY: include every other authorized mail provider before publishing.")
    else:
        record = spf["records"][0]
        cost = lookup_cost(record)
        if cost > 10:
            spf.update(status="review", message="More than 10 directly counted DNS mechanisms: SPF PermError risk.")
        elif "redirect=" in record.lower() or "%{" in record:
            spf.update(status="review", message="SPF redirect/macros require manual assessment; no safe automatic edit.")
        elif not outbound_ip:
            spf.update(status="not_checked", message="Enter a CONFIRMED SMTP outbound IP for SPF authorization checks.")
        else:
            status, explanation = _ip_check(record, outbound_ip)
            spf.update(status=status, message=explanation)
            if status == "needs_action":
                value, note = suggested_spf(record, outbound_ip)
                if value and value != record:
                    spf["proposal"] = _proposal(
                        "replace_existing", domain, value,
                        note + " Keep all existing legitimate senders. Publish ONE SPF TXT only.")
        if cost > 0:
            results["notes"].append(
                "SPF may involve a/mx/include recursive DNS mechanisms. This check is NOT a full RFC 7208 evaluation.")

    dkim = results["dkim"]
    dkim["records"] = [r for r in query(dkim["name"], "TXT")
                       if r.lower().startswith("v=dkim1") or "p=" in r.lower()]
    if len(dkim["records"]) > 1:
        dkim.update(status="needs_action", message="Multiple DKIM key TXT records at one selector; check DNS.")
    elif not dkim["records"]:
        dkim.update(status="needs_action", message="DKIM key not published for this selector. Configure a signer and obtain its PUBLIC key first. Never invent a p= value.")
    else:
        tags = _tags(dkim["records"][0])
        key = tags.get("p", "")
        try:
            decoded = base64.b64decode(key, validate=True)
            plausible = len(decoded) >= 64
        except (binascii.Error, ValueError):
            plausible = False
        if tags.get("v", "DKIM1").upper() != "DKIM1" or not plausible:
            dkim.update(status="needs_action", message="DKIM public-key syntax missing, revoked or malformed.")
        else:
            dkim.update(status="verified_dns", message="Public key syntax and TXT publication checked; real message signing is NOT verified.")

    dmarc = results["dmarc"]
    dmarc["records"] = [r for r in query(dmarc["name"], "TXT")
                        if r.lower().startswith("v=dmarc1")]
    if len(dmarc["records"]) > 1:
        dmarc.update(status="needs_action", message="Multiple DMARC policies at this name; consolidate manually.")
    elif not dmarc["records"]:
        dmarc.update(status="needs_action", message="No DMARC policy found.")
        dmarc["proposal"] = _proposal(
            "create_after_review", dmarc["name"], "v=DMARC1; p=none",
            "Monitoring-only starting point. Plan reporting, alignment and later enforcement separately.")
    else:
        tags = _tags(dmarc["records"][0])
        if tags.get("p", "").lower() in ("none", "quarantine", "reject"):
            dmarc.update(status="verified_dns", message="Published DMARC policy syntax/p= checked; actual message alignment not verified.")
        else:
            dmarc.update(status="needs_action", message="DMARC p= is absent or invalid; revise existing record without discarding reporting tags.")

    results["summary"] = (
        "dns_records_verified_live_signing_unverified"
        if all(results[k]["status"] == "verified_dns" for k in ("ownership", "spf", "dkim", "dmarc"))
        else "attention_or_further_evidence_required"
    )
    return results
