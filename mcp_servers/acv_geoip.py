#!/usr/bin/env python3
"""
acv_geoip.py — shared GeoIP/ASN enrichment for the unified logging pipeline.

Every IP-bearing record gets geo + asn stamped AT EMIT TIME via enrich(ip). This
ends the "identified Tor/AWS actors by hand" gap.

DATA SOURCE: MaxMind GeoLite2 (free, needs a license key — see SETUP below). The
module is FAIL-SAFE: if the DBs are absent it returns null geo/asn (never errors),
and a built-in static fallback still labels well-known ranges (Tor exits, major
clouds) so enrichment is useful even before the DBs land.

SETUP (one-time, on the box):
  1. Free MaxMind account -> license key: https://www.maxmind.com/en/geolite2/signup
  2. Download the two DBs (City + ASN):
       LICENSE_KEY=xxxx
       for db in GeoLite2-City GeoLite2-ASN; do
         curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=$db&license_key=$LICENSE_KEY&suffix=tar.gz" \\
           | tar xz -C /tmp && cp /tmp/$db_*/$db.mmdb /opt/acv/
       done
  3. pip install geoip2 --break-system-packages   (or into the trex venv)
  4. cron monthly refresh (DBs update weekly): same curl in a monthly timer.

Usage:
  from acv_geoip import enrich
  geo, asn = enrich("185.220.101.28")
  # geo -> {"country":"..","city":"..","lat":..,"lon":..} or None
  # asn -> {"num":.., "org":".."} or None
  # plus a "tags" list for known-range flags (tor_exit, aws, gcp, ...)
"""
import ipaddress, os

CITY_DB = os.environ.get("GEOIP_CITY_DB", "/opt/acv/GeoLite2-City.mmdb")
ASN_DB  = os.environ.get("GEOIP_ASN_DB",  "/opt/acv/GeoLite2-ASN.mmdb")

try:
    import geoip2.database as _g
    _CITY = _g.Reader(CITY_DB) if os.path.exists(CITY_DB) else None
    _ASN  = _g.Reader(ASN_DB)  if os.path.exists(ASN_DB)  else None
except Exception:
    _CITY = _ASN = None

# ── static fallback: well-known ranges we care about, so enrichment is useful even
#    with no MaxMind DB. Extend as new actors appear. (This is a coarse net, not a
#    substitute for the DB — it flags, it doesn't geolocate.)
_KNOWN_RANGES = [
    # (cidr, tag, note)
    ("185.220.100.0/22", "tor_exit", "known Tor exit relay block"),
    ("185.220.96.0/22",  "tor_exit", "known Tor exit relay block"),
    ("171.25.193.0/24",  "tor_exit", "Tor exit (DFRI)"),
    ("204.8.96.0/22",    "tor_exit", "Tor exit"),
    ("3.0.0.0/8",        "aws",      "AWS EC2"),
    ("15.0.0.0/8",       "aws",      "AWS"),
    ("18.0.0.0/8",       "aws",      "AWS EC2"),
    ("34.192.0.0/10",    "aws",      "AWS EC2"),
    ("35.152.0.0/13",    "aws",      "AWS"),
    ("52.0.0.0/8",       "aws",      "AWS EC2"),
    ("54.0.0.0/8",       "aws",      "AWS EC2"),
    ("34.64.0.0/10",     "gcp",      "Google Cloud"),
    ("35.184.0.0/13",    "gcp",      "Google Cloud"),
    ("35.192.0.0/14",    "gcp",      "Google Cloud"),
    ("104.196.0.0/14",   "gcp",      "Google Cloud"),
    ("20.0.0.0/8",       "azure",    "Microsoft Azure"),
    ("40.64.0.0/10",     "azure",    "Microsoft Azure"),
    ("104.16.0.0/12",    "cloudflare","Cloudflare (egress/proxy — real origin upstream)"),
    ("172.64.0.0/13",    "cloudflare","Cloudflare"),
]
_NETS = [(ipaddress.ip_network(c), tag, note) for c, tag, note in _KNOWN_RANGES]

def _first(ip):
    return str(ip).split(",")[0].strip() if ip else ""

def _static_tags(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    out = []
    for net, tag, note in _NETS:
        if addr.version == net.version and addr in net:
            out.append(tag)
    return out

def enrich(ip):
    """Return (geo, asn) dicts (or None) for an IP. Fail-safe: never raises.
    Adds a 'tags' key inside geo for known-range flags even when the DB is absent."""
    ip = _first(ip)
    if not ip:
        return None, None
    geo = asn = None
    if _CITY:
        try:
            r = _CITY.city(ip)
            geo = {"country": r.country.iso_code, "city": r.city.name,
                   "lat": (r.location.latitude if r.location else None),
                   "lon": (r.location.longitude if r.location else None)}
        except Exception:
            geo = None
    if _ASN:
        try:
            r = _ASN.asn(ip)
            asn = {"num": r.autonomous_system_number, "org": r.autonomous_system_organization}
        except Exception:
            asn = None
    tags = _static_tags(ip)
    if tags:
        geo = geo or {}
        geo["tags"] = tags
    return geo, asn

def enabled():
    """True if the MaxMind DBs are loaded (full geolocation). False = fallback-only."""
    return bool(_CITY and _ASN)

if __name__ == "__main__":
    import sys, json
    ips = sys.argv[1:] or ["185.220.101.28", "52.24.112.111", "35.186.14.156", "8.8.8.8"]
    print(f"MaxMind DBs loaded: {enabled()} (False = static-fallback tags only)\n")
    for ip in ips:
        g, a = enrich(ip)
        print(f"{ip:20} geo={json.dumps(g)} asn={json.dumps(a)}")
