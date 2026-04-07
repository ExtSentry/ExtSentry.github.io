#!/usr/bin/env python3
"""
ExtSentry - Browser Extension Threat Intelligence Feed Generator (v2 - Audited)
Generates properly formatted feeds for each target platform.
Auto-fetches the latest CSV from GitHub, falls back to local file.
"""

import csv
import json
import uuid
import hashlib
from datetime import datetime, timezone
import os
import io
import xml.etree.ElementTree as ET
from xml.dom import minidom

GITHUB_CSV_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/Browser%20Extensions/browser_extensions_list.csv"
LOCAL_CSV = "browser_extensions_list.csv"
OUTPUT_DIR = "feeds"
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
DATE_TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")

# Standard STIX 2.1 TLP marking definition IDs (these are mandated by the spec)
TLP_CLEAR_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"

def fetch_csv():
    """Fetch latest CSV from GitHub. Returns CSV text or None on failure."""
    try:
        import urllib.request
        print(f"Fetching latest CSV from GitHub...")
        req = urllib.request.Request(GITHUB_CSV_URL, headers={"User-Agent": "ExtSentry-FeedGenerator/2.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read().decode('utf-8')
            # Save a local copy
            with open(LOCAL_CSV, 'w', encoding='utf-8') as f:
                f.write(data)
            print(f"  Fetched {len(data):,} bytes, saved local copy to {LOCAL_CSV}")
            return data
    except Exception as e:
        print(f"  GitHub fetch failed: {e}")
        return None

def load_csv():
    # Try GitHub first, fall back to local file
    csv_text = fetch_csv()
    if csv_text:
        reader = csv.DictReader(io.StringIO(csv_text))
    else:
        # Fall back to local file
        for path in [LOCAL_CSV, "/mnt/user-data/uploads/browser_extensions_list.csv"]:
            if os.path.exists(path):
                print(f"  Using local file: {path}")
                reader = csv.DictReader(open(path, newline='', encoding='utf-8'))
                break
        else:
            raise FileNotFoundError("No CSV found locally and GitHub fetch failed")

    rows = []
    for r in reader:
        rows.append({
            'name': r['browser_extension'].strip(),
            'id': r['browser_extension_id'].strip(),
            'wildcard': r['browser_extension_id_wildcard'].strip(),
            'category': r['metadata_category'].strip(),
            'type': r['metadata_type'].strip(),
            'link': r['metadata_link'].strip(),
            'comment': r['metadata_comment'].strip(),
            'sha256': r.get('crx_file_sha256', '').strip()
        })
    return rows

def deterministic_uuid(seed):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"extsentry:{seed}"))

SEVERITY_MAP = {
    "malicious": "critical", "phishing": "high", "deceptive": "high",
    "offensive": "medium", "greyware": "medium", "sensitive": "low",
    "privacy": "low", "Defense Evasion": "high"
}

# ─── STIX 2.1 Bundle (OpenCTI / TAXII) ───
def generate_stix(rows):
    identity_id = f"identity--{deterministic_uuid('extsentry-identity')}"
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": NOW,
        "modified": NOW,
        "name": "ExtSentry - Browser Extension Threat Intelligence",
        "description": "Community-driven browser extension threat intelligence feed maintained by mthcht",
        "identity_class": "organization",
        "object_marking_refs": [TLP_CLEAR_ID]
    }

    objects = [identity]

    category_to_malware_type = {
        "malware": "trojan",
        "compromised": "backdoor",
        "scam": "adware",
        "PUP": "adware",
        "cryptocurrency": "resource-exploitation",
        "PROXY/VPN": "unknown",
        "RMM": "remote-access-trojan",
        "Credential Access": "credential-exploitation",
        "Defense Evasion": "unknown",
        "password manager": "unknown"
    }

    for row in rows:
        ext_id = row['id']
        if not ext_id:
            continue

        indicator_id = f"indicator--{deterministic_uuid(ext_id)}"
        display_name = row['name'] or row['comment'] or ext_id

        labels = [l for l in [row['category'], row['type']] if l]

        external_refs = []
        if row['link'] and row['link'] not in ('fixme', 'N/A'):
            external_refs.append({
                "source_name": "reference",
                "url": row['link']
            })
        external_refs.append({
            "source_name": "chrome-webstore",
            "url": f"https://chromewebstore.google.com/detail/{ext_id}",
            "external_id": ext_id
        })

        safe_name = display_name.replace("'", "\\'")
        pattern = f"[software:x_extension_id = '{ext_id}']"
        if row['sha256']:
            pattern = f"[software:x_extension_id = '{ext_id}'] OR [file:hashes.'SHA-256' = '{row['sha256']}']"

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": NOW,
            "modified": NOW,
            "name": f"Malicious Browser Extension: {display_name}",
            "description": f"Browser extension ID: {ext_id}. Category: {row['category']}. Type: {row['type']}. {row['comment']}" + (f". CRX SHA-256: {row['sha256']}" if row['sha256'] else ""),
            "indicator_types": ["malicious-activity"] if row['type'] in ('malicious', 'phishing') else ["anomalous-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": NOW,
            "confidence": 85 if row['type'] == 'malicious' else 50,
            "labels": labels,
            "external_references": external_refs,
            "object_marking_refs": [TLP_CLEAR_ID],
            "created_by_ref": identity_id
        }
        objects.append(indicator)

        if row['type'] == 'malicious' or row['category'] == 'malware':
            malware_id = f"malware--{deterministic_uuid(ext_id + '-malware')}"
            malware_type = category_to_malware_type.get(row['category'], 'unknown')
            malware = {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": NOW,
                "modified": NOW,
                "name": display_name,
                "description": f"Malicious browser extension: {row['comment']}",
                "malware_types": [malware_type],
                "is_family": False,
                "labels": labels,
                "created_by_ref": identity_id,
                "object_marking_refs": [TLP_CLEAR_ID]
            }
            objects.append(malware)

            rel_id = f"relationship--{deterministic_uuid(ext_id + '-rel')}"
            relationship = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": NOW,
                "modified": NOW,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": malware_id,
                "created_by_ref": identity_id,
                "object_marking_refs": [TLP_CLEAR_ID]
            }
            objects.append(relationship)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{deterministic_uuid('extsentry-bundle')}",
        "objects": objects
    }

    with open(os.path.join(OUTPUT_DIR, "stix2_bundle.json"), 'w') as f:
        json.dump(bundle, f, indent=2)
    print(f"  STIX 2.1 Bundle: {len(objects)} objects")

# ─── MISP Event JSON ───
def generate_misp(rows):
    event = {
        "Event": {
            "info": "ExtSentry - Malicious/Suspicious Browser Extensions IOC Feed",
            "threat_level_id": "2",
            "analysis": "2",
            "distribution": "3",
            "date": DATE_TODAY,
            "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
            "published": False,
            "uuid": deterministic_uuid("misp-event"),
            "Orgc": {
                "name": "ExtSentry",
                "uuid": deterministic_uuid("misp-org")
            },
            "Tag": [
                {"name": "tlp:white"},
                {"name": "type:OSINT"},
                {"name": "osint:source-type=\"technical-report\""},
                {"name": "workflow:state=\"complete\""}
            ],
            "Attribute": [],
            "Object": []
        }
    }

    for i, row in enumerate(rows):
        if not row['id']:
            continue

        display_name = row['name'] or row['comment'] or row['id']

        attr = {
            "uuid": deterministic_uuid(f"misp-attr-{row['id']}"),
            "type": "text",
            "category": "Other",
            "to_ids": False,
            "value": row['id'],
            "comment": f"{display_name} | Category: {row['category']} | Type: {row['type']} | {row['comment']}",
            "distribution": "5",
            "Tag": [
                {"name": f"extsentry:category=\"{row['category']}\""},
                {"name": f"extsentry:type=\"{row['type']}\""}
            ]
        }
        event["Event"]["Attribute"].append(attr)

        if row['sha256']:
            sha_attr = {
                "uuid": deterministic_uuid(f"misp-attr-sha256-{row['id']}"),
                "type": "sha256",
                "category": "Payload delivery",
                "to_ids": True,
                "value": row['sha256'],
                "comment": f"CRX file hash for {display_name} ({row['id']})",
                "distribution": "5",
                "Tag": [
                    {"name": f"extsentry:category=\"{row['category']}\""},
                    {"name": f"extsentry:type=\"{row['type']}\""}
                ]
            }
            event["Event"]["Attribute"].append(sha_attr)

        obj = {
            "uuid": deterministic_uuid(f"misp-obj-{row['id']}"),
            "name": "annotation",
            "meta-category": "misc",
            "description": f"Suspicious/Malicious browser extension: {display_name}",
            "template_uuid": deterministic_uuid("misp-obj-template"),
            "template_version": "1",
            "Attribute": [
                {"object_relation": "text", "type": "text", "value": row['id'],
                 "comment": "Browser Extension ID", "to_ids": False},
                {"object_relation": "text", "type": "text", "value": display_name,
                 "comment": "Extension Name", "to_ids": False},
                {"object_relation": "text", "type": "text", "value": row['category'],
                 "comment": "Threat Category", "to_ids": False},
                {"object_relation": "text", "type": "text", "value": row['type'],
                 "comment": "Threat Type", "to_ids": False},
            ]
        }
        if row['sha256']:
            obj["Attribute"].append(
                {"object_relation": "text", "type": "sha256", "value": row['sha256'],
                 "comment": "CRX File SHA-256", "to_ids": True}
            )
        if row['link'] and row['link'] not in ('fixme', 'N/A'):
            obj["Attribute"].append(
                {"object_relation": "text", "type": "link", "value": row['link'],
                 "comment": "Reference URL", "to_ids": False}
            )
        event["Event"]["Object"].append(obj)

    with open(os.path.join(OUTPUT_DIR, "misp_event.json"), 'w') as f:
        json.dump(event, f, indent=2)
    print(f"  MISP Event: {len(event['Event']['Attribute'])} attributes, {len(event['Event']['Object'])} objects")

# ─── MISP Warning Lists ───
def generate_misp_warninglists(rows):
    warninglist = {
        "name": "ExtSentry - Known Malicious/Suspicious Browser Extension IDs",
        "version": int(datetime.now(timezone.utc).strftime("%Y%m%d")),
        "description": "List of known malicious, suspicious, and potentially unwanted browser extension IDs. Maintained by mthcht.",
        "type": "string",
        "matching_attributes": ["text", "filename", "other"],
        "list": [row['id'] for row in rows if row['id']]
    }

    with open(os.path.join(OUTPUT_DIR, "misp_warninglist.json"), 'w') as f:
        json.dump(warninglist, f, indent=2)
    print(f"  MISP Warning List: {len(warninglist['list'])} entries")

# ─── Enriched CSV ───
def generate_csv(rows):
    fieldnames = [
        'extension_id', 'extension_name', 'wildcard_pattern', 'category', 'threat_type',
        'reference_url', 'description', 'chrome_webstore_url', 'severity',
        'crx_sha256', 'first_seen', 'feed_source'
    ]

    with open(os.path.join(OUTPUT_DIR, "extsentry_ioc_feed.csv"), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            if not row['id']:
                continue
            w.writerow({
                'extension_id': row['id'],
                'extension_name': row['name'] or row['comment'] or '',
                'wildcard_pattern': row['wildcard'],
                'category': row['category'],
                'threat_type': row['type'],
                'reference_url': row['link'],
                'description': row['comment'],
                'chrome_webstore_url': f"https://chromewebstore.google.com/detail/{row['id']}",
                'severity': SEVERITY_MAP.get(row['type'], 'medium'),
                'crx_sha256': row['sha256'],
                'first_seen': DATE_TODAY,
                'feed_source': 'ExtSentry (github.com/mthcht/awesome-lists)'
            })
    print(f"  Enriched CSV: {sum(1 for r in rows if r['id'])} entries")

# ─── JSON Feed ───
def generate_json(rows):
    feed = {
        "feed_name": "ExtSentry - Browser Extension Threat Intelligence",
        "feed_version": "1.0",
        "generated": NOW,
        "source": "https://github.com/mthcht/awesome-lists",
        "license": "TLP:CLEAR",
        "total_indicators": sum(1 for r in rows if r['id']),
        "categories": {},
        "indicators": []
    }

    cats = {}
    for row in rows:
        if not row['id']:
            continue
        c = row['category']
        cats[c] = cats.get(c, 0) + 1
        feed["indicators"].append({
            "extension_id": row['id'],
            "extension_name": row['name'] or None,
            "wildcard_pattern": row['wildcard'],
            "category": row['category'],
            "threat_type": row['type'],
            "reference_url": row['link'] or None,
            "description": row['comment'],
            "crx_sha256": row['sha256'] or None,
            "chrome_webstore_url": f"https://chromewebstore.google.com/detail/{row['id']}"
        })
    feed["categories"] = cats

    with open(os.path.join(OUTPUT_DIR, "extsentry_feed.json"), 'w') as f:
        json.dump(feed, f, indent=2)
    print(f"  JSON Feed: {len(feed['indicators'])} indicators")

# ─── Splunk Lookup CSV ───
def generate_splunk(rows):
    fieldnames = ['browser_extension_id', 'browser_extension_id_wildcard', 'extension_name',
                  'category', 'threat_type', 'severity', 'crx_sha256', 'description', 'reference_url']

    with open(os.path.join(OUTPUT_DIR, "splunk_lookup_browser_extensions.csv"), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            if not row['id']:
                continue
            w.writerow({
                'browser_extension_id': row['id'],
                'browser_extension_id_wildcard': row['wildcard'],
                'extension_name': row['name'] or row['comment'] or '',
                'category': row['category'],
                'threat_type': row['type'],
                'severity': SEVERITY_MAP.get(row['type'], 'medium'),
                'crx_sha256': row['sha256'],
                'description': row['comment'],
                'reference_url': row['link']
            })
    print(f"  Splunk Lookup CSV generated")

# ─── Sigma Rules ───
def generate_sigma(rows):
    all_ids = [r['id'] for r in rows if r['id']]

    ids_by_category = {}
    for row in rows:
        if not row['id']:
            continue
        c = row['category']
        if c not in ids_by_category:
            ids_by_category[c] = []
        ids_by_category[c].append(row['id'])

    rules = []

    rule = f"""title: Suspicious Browser Extension ID in Process CommandLine - ExtSentry
id: {deterministic_uuid('sigma-proc')}
status: experimental
description: |
    Detects browser extension IDs flagged by the ExtSentry threat intelligence feed
    appearing in process command line arguments. This may indicate browser launch with
    a malicious extension or extension-related tooling.
references:
    - https://github.com/mthcht/awesome-lists
author: ExtSentry / mthcht
date: {DATE_TODAY}
modified: {DATE_TODAY}
tags:
    - attack.persistence
    - attack.t1176
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
"""
    for eid in all_ids:
        rule += f"            - '{eid}'\n"
    rule += """    condition: selection
falsepositives:
    - Legitimate use of listed extensions (review each match individually)
    - Browser auto-update processes referencing extension directories
level: medium
"""
    rules.append(rule)

    rule2 = f"""title: Suspicious Browser Extension ID in File Path - ExtSentry
id: {deterministic_uuid('sigma-file')}
status: experimental
description: |
    Detects file operations involving directories matching known malicious browser
    extension IDs from the ExtSentry feed. Extensions are stored in directories
    named by their extension ID under the browser profile.
references:
    - https://github.com/mthcht/awesome-lists
author: ExtSentry / mthcht
date: {DATE_TODAY}
modified: {DATE_TODAY}
tags:
    - attack.persistence
    - attack.t1176
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
"""
    for eid in all_ids:
        rule2 += f"            - '{eid}'\n"
    rule2 += """    condition: selection
falsepositives:
    - Legitimate extensions with matching IDs (unlikely given uniqueness)
level: medium
"""
    rules.append(rule2)

    rule3 = f"""title: Suspicious Browser Extension ID in Registry - ExtSentry
id: {deterministic_uuid('sigma-reg')}
status: experimental
description: |
    Detects registry operations referencing known malicious browser extension IDs
    from the ExtSentry feed. Chrome/Edge store extension metadata in the Windows
    registry under the extension ID.
references:
    - https://github.com/mthcht/awesome-lists
author: ExtSentry / mthcht
date: {DATE_TODAY}
modified: {DATE_TODAY}
tags:
    - attack.persistence
    - attack.t1176
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains:
"""
    for eid in all_ids:
        rule3 += f"            - '{eid}'\n"
    rule3 += """    condition: selection
falsepositives:
    - Legitimate extensions with matching IDs
level: medium
"""
    rules.append(rule3)

    for cat, ids in ids_by_category.items():
        level = "high" if cat in ("malware", "Credential Access", "compromised") else "medium"
        cat_clean = cat.replace("/", "_").replace(" ", "_")
        rule = f"""title: '{cat}' Browser Extension Detected in CommandLine - ExtSentry
id: {deterministic_uuid(f'sigma-{cat}')}
status: experimental
description: Detects browser extensions categorized as '{cat}' in the ExtSentry feed
references:
    - https://github.com/mthcht/awesome-lists
author: ExtSentry / mthcht
date: {DATE_TODAY}
modified: {DATE_TODAY}
tags:
    - attack.persistence
    - attack.t1176
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
"""
        for eid in ids:
            rule += f"            - '{eid}'\n"
        rule += f"""    condition: selection
falsepositives:
    - Legitimate use of extensions in this category
level: {level}
"""
        rules.append(rule)

    sha_rows = [r for r in rows if r['sha256']]
    if sha_rows:
        sha_rule = f"""title: Malicious Browser Extension CRX File Hash - ExtSentry
id: {deterministic_uuid('sigma-sha256')}
status: experimental
description: |
    Detects known malicious browser extension CRX files by their SHA-256 hash.
    Hashes sourced from the ExtSentry threat intelligence feed.
references:
    - https://github.com/mthcht/awesome-lists
author: ExtSentry
date: {DATE_TODAY}
modified: {DATE_TODAY}
tags:
    - attack.persistence
    - attack.t1176
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Hashes|contains:
"""
        for r in sha_rows:
            sha_rule += f"            - '{r['sha256']}'\n"
        sha_rule += f"""    filter_selection:
        sha256:
"""
        for r in sha_rows:
            sha_rule += f"            - '{r['sha256']}'\n"
        sha_rule += f"""    condition: selection or filter_selection
falsepositives:
    - Unlikely
level: critical
"""
        rules.append(sha_rule)

    with open(os.path.join(OUTPUT_DIR, "sigma_rules_browser_extensions.yml"), 'w') as f:
        f.write("---\n".join(rules))
    print(f"  Sigma Rules: {len(rules)} rules (3 logsource types + {len(ids_by_category)} per-category)")

# ─── OpenIOC 1.1 ───
def generate_openioc(rows):
    ioc = ET.Element("ioc", {
        "xmlns": "http://schemas.mandiant.com/2010/ioc",
        "id": deterministic_uuid("openioc-main"),
        "last-modified": NOW
    })

    short_desc = ET.SubElement(ioc, "short_description")
    short_desc.text = "ExtSentry - Malicious Browser Extension IOCs"

    desc = ET.SubElement(ioc, "description")
    desc.text = "Browser extension IDs flagged as malicious/suspicious. Matches extension IDs in file paths and registry entries. Source: github.com/mthcht/awesome-lists"

    authored_date = ET.SubElement(ioc, "authored_date")
    authored_date.text = NOW

    definition = ET.SubElement(ioc, "definition")
    indicator_or = ET.SubElement(definition, "Indicator", {"operator": "OR", "id": deterministic_uuid("openioc-or")})

    for row in rows:
        if not row['id']:
            continue

        comment_text = f"{row['category']} | {row['type']} | {row['comment']}"

        ind_file = ET.SubElement(indicator_or, "IndicatorItem", {
            "id": deterministic_uuid(f"openioc-file-{row['id']}"),
            "condition": "contains"
        })
        ctx_file = ET.SubElement(ind_file, "Context", {
            "document": "FileItem",
            "search": "FileItem/FullPath",
            "type": "mir"
        })
        content_file = ET.SubElement(ind_file, "Content", {"type": "string"})
        content_file.text = row['id']
        comment_el = ET.SubElement(ind_file, "Comment")
        comment_el.text = comment_text

        ind_reg = ET.SubElement(indicator_or, "IndicatorItem", {
            "id": deterministic_uuid(f"openioc-reg-{row['id']}"),
            "condition": "contains"
        })
        ctx_reg = ET.SubElement(ind_reg, "Context", {
            "document": "RegistryItem",
            "search": "RegistryItem/Path",
            "type": "mir"
        })
        content_reg = ET.SubElement(ind_reg, "Content", {"type": "string"})
        content_reg.text = row['id']
        comment_el2 = ET.SubElement(ind_reg, "Comment")
        comment_el2.text = comment_text

        if row['sha256']:
            ind_hash = ET.SubElement(indicator_or, "IndicatorItem", {
                "id": deterministic_uuid(f"openioc-hash-{row['id']}"),
                "condition": "is"
            })
            ctx_hash = ET.SubElement(ind_hash, "Context", {
                "document": "FileItem",
                "search": "FileItem/Sha256sum",
                "type": "mir"
            })
            content_hash = ET.SubElement(ind_hash, "Content", {"type": "string"})
            content_hash.text = row['sha256']
            comment_hash = ET.SubElement(ind_hash, "Comment")
            comment_hash.text = f"CRX SHA-256 for {comment_text}"

    xml_str = minidom.parseString(ET.tostring(ioc, encoding='unicode')).toprettyxml(indent="  ")
    with open(os.path.join(OUTPUT_DIR, "openioc_browser_extensions.ioc"), 'w') as f:
        f.write(xml_str)
    print(f"  OpenIOC: {sum(1 for r in rows if r['id'])} indicator items (file + registry)")

# ─── YARA Rules ───
def generate_yara(rows):
    rules = []
    cats = {}
    for row in rows:
        if not row['id']:
            continue
        c = row['category'].replace("/", "_").replace(" ", "_")
        if c not in cats:
            cats[c] = []
        cats[c].append(row)

    for cat, cat_rows in cats.items():
        strings_block = []
        for i, row in enumerate(cat_rows):
            strings_block.append(f'        $ext_{i} = "{row["id"]}" ascii wide')

        rule = f"""rule ExtSentry_{cat}_BrowserExtensions
{{
    meta:
        description = "Detects browser extension IDs categorized as {cat} by ExtSentry"
        author = "ExtSentry / mthcht"
        date = "{DATE_TODAY}"
        reference = "https://github.com/mthcht/awesome-lists"
        category = "{cat}"
        tlp = "WHITE"

    strings:
{chr(10).join(strings_block)}

    condition:
        any of ($ext_*)
}}
"""
        rules.append(rule)

    sha_rows = [r for r in rows if r['sha256']]
    if sha_rows:
        hash_conditions = []
        for row in sha_rows:
            hash_conditions.append(f'        hash.sha256(0, filesize) == "{row["sha256"]}"')
        hash_rule = f"""import "hash"

rule ExtSentry_CRX_SHA256_Hashes
{{
    meta:
        description = "Detects known malicious CRX files by SHA-256 hash"
        author = "ExtSentry"
        date = "{DATE_TODAY}"
        reference = "https://github.com/mthcht/awesome-lists"
        tlp = "WHITE"

    condition:
{chr(10).join(f'        {c} or' for c in hash_conditions[:-1])}
{hash_conditions[-1]}
}}
"""
        rules.append(hash_rule)

    with open(os.path.join(OUTPUT_DIR, "yara_browser_extensions.yar"), 'w') as f:
        f.write("\n".join(rules))
    print(f"  YARA Rules: {len(rules)} rules by category")

# ─── Suricata Rules ───
def generate_suricata(rows):
    rules = []
    rules.append("# ExtSentry Browser Extension Suricata Rules")
    rules.append("# NOTE: Most browser extension traffic is HTTPS. These rules require TLS")
    rules.append("# inspection/decryption to be effective, or will match on non-encrypted")
    rules.append("# traffic only (e.g., update checks on some enterprise networks).")
    rules.append("# Consider using Suricata datasets for better performance with large IOC lists.")
    rules.append("")

    sid = 9000001

    for row in rows:
        if not row['id']:
            continue
        display = (row['name'] or row['comment'] or row['id'])[:60].replace('"', "'").replace(';', ',')
        severity = 1 if row['type'] == 'malicious' else 2

        rule = (
            f'alert http $HOME_NET any -> $EXTERNAL_NET any '
            f'(msg:"EXTSENTRY - Suspicious Browser Extension: {display}"; '
            f'flow:to_server,established; '
            f'http.uri; content:"{row["id"]}"; '
            f'reference:url,github.com/mthcht/awesome-lists; '
            f'classtype:policy-violation; '
            f'sid:{sid}; rev:1; '
            f'metadata:category {row["category"]}, type {row["type"]}, '
            f'severity {SEVERITY_MAP.get(row["type"], "medium")};)'
        )
        rules.append(rule)
        sid += 1

    with open(os.path.join(OUTPUT_DIR, "suricata_browser_extensions.rules"), 'w') as f:
        f.write("\n".join(rules))
    print(f"  Suricata Rules: {sid - 9000001} rules (with flow + http.uri buffer)")

# ─── OpenCTI CSV Import Format ───
def generate_opencti_csv(rows):
    fieldnames = ['type', 'name', 'description', 'pattern', 'pattern_type',
                  'x_opencti_main_observable_type', 'labels', 'confidence',
                  'valid_from', 'x_opencti_score']

    with open(os.path.join(OUTPUT_DIR, "opencti_import.csv"), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            if not row['id']:
                continue
            display_name = row['name'] or row['comment'] or row['id']
            confidence = 85 if row['type'] == 'malicious' else 50
            score = 90 if row['type'] == 'malicious' else 40
            w.writerow({
                'type': 'indicator',
                'name': f"Browser Extension: {display_name}",
                'description': f"Extension ID: {row['id']}. Category: {row['category']}. {row['comment']}. Ref: {row['link']}" + (f". CRX SHA-256: {row['sha256']}" if row['sha256'] else ""),
                'pattern': f"[software:x_extension_id = '{row['id']}']",
                'pattern_type': 'stix',
                'x_opencti_main_observable_type': 'Software',
                'labels': f"{row['category']},{row['type']},browser-extension",
                'confidence': str(confidence),
                'valid_from': NOW,
                'x_opencti_score': str(score)
            })
    print(f"  OpenCTI CSV: generated")

# ─── Simple IOC lists (just IDs, one per line) ───
# "sensitive" type = not malicious, everything else = malicious
def generate_plain_lists(rows):
    all_ids = [r['id'] for r in rows if r['id']]
    malicious_ids = [r['id'] for r in rows if r['id'] and r['type'] != 'sensitive']
    suspicious_ids = [r['id'] for r in rows if r['id'] and r['type'] == 'sensitive']
    sha256_hashes = [r['sha256'] for r in rows if r['sha256']]

    with open(os.path.join(OUTPUT_DIR, "ioc_all_extension_ids.txt"), 'w') as f:
        f.write("\n".join(all_ids))
    with open(os.path.join(OUTPUT_DIR, "ioc_malicious_extension_ids.txt"), 'w') as f:
        f.write("\n".join(malicious_ids))
    with open(os.path.join(OUTPUT_DIR, "ioc_suspicious_extension_ids.txt"), 'w') as f:
        f.write("\n".join(suspicious_ids))
    if sha256_hashes:
        with open(os.path.join(OUTPUT_DIR, "ioc_crx_sha256_hashes.txt"), 'w') as f:
            f.write("\n".join(sha256_hashes))
    print(f"  Plain IOC Lists: {len(all_ids)} all, {len(malicious_ids)} malicious, {len(suspicious_ids)} suspicious (sensitive only), {len(sha256_hashes)} SHA-256 hashes")

# ─── Elasticsearch / Kibana ───
def generate_elastic(rows):
    all_ids = [r['id'] for r in rows if r['id']]

    rule = {
        "id": deterministic_uuid("elastic-rule"),
        "name": "ExtSentry - Suspicious Browser Extension Activity",
        "description": "Detects browser extension IDs flagged by the ExtSentry threat intelligence feed in process arguments, file paths, or registry entries.",
        "risk_score": 50,
        "severity": "medium",
        "type": "query",
        "language": "kuery",
        "query": " or ".join([
            f'process.command_line: "*{eid}*"' for eid in all_ids[:200]
        ]),
        "index": [
            "logs-endpoint.events.*",
            "winlogbeat-*",
            "logs-windows.*",
            "endgame-*"
        ],
        "interval": "5m",
        "from": "now-6m",
        "tags": ["ExtSentry", "Browser Extension", "Threat Intel", "T1176"],
        "note": f"Full list contains {len(all_ids)} extension IDs. For complete coverage, use the threat intel NDJSON feed with an Indicator Match rule instead of this query rule. Import stix2_bundle.json via Custom Threat Intelligence integration for best results.",
        "references": ["https://github.com/mthcht/awesome-lists"],
        "author": ["ExtSentry", "mthcht"],
        "license": "TLP:CLEAR",
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": "TA0003",
                "name": "Persistence",
                "reference": "https://attack.mitre.org/tactics/TA0003/"
            },
            "technique": [{
                "id": "T1176",
                "name": "Browser Extensions",
                "reference": "https://attack.mitre.org/techniques/T1176/"
            }]
        }]
    }

    with open(os.path.join(OUTPUT_DIR, "elastic_detection_rule.ndjson"), 'w') as f:
        json.dump(rule, f)
        f.write("\n")

    with open(os.path.join(OUTPUT_DIR, "elastic_threat_intel.ndjson"), 'w') as f:
        for row in rows:
            if not row['id']:
                continue
            display_name = row['name'] or row['comment'] or row['id']
            doc = {
                "@timestamp": NOW,
                "event": {
                    "kind": "enrichment",
                    "category": ["threat"],
                    "type": ["indicator"],
                    "dataset": "ti_extsentry.indicator",
                    "module": "threat_intel"
                },
                "threat": {
                    "indicator": {
                        "type": "software",
                        "name": display_name,
                        "description": f"Browser extension ID: {row['id']}. {row['comment']}",
                        "provider": "ExtSentry",
                        "confidence": "High" if row['type'] == 'malicious' else "Medium",
                        "file": {"hash": {"sha256": row['sha256']}} if row['sha256'] else None,
                        "first_seen": NOW,
                        "modified_at": NOW,
                        "reference": row['link'] if row['link'] not in ('fixme', 'N/A') else None,
                        "marking": {
                            "tlp": "CLEAR",
                            "tlp_version": "2.0"
                        }
                    },
                    "feed": {
                        "name": "ExtSentry Browser Extension Feed"
                    }
                },
                "extsentry": {
                    "extension_id": row['id'],
                    "wildcard_pattern": row['wildcard'],
                    "category": row['category'],
                    "threat_type": row['type'],
                    "severity": SEVERITY_MAP.get(row['type'], 'medium'),
                    "crx_sha256": row['sha256'] or None
                },
                "tags": ["extsentry", f"extsentry-{row['category']}", row['type'], "browser-extension"]
            }
            f.write(json.dumps(doc) + "\n")
    print(f"  Elastic: Detection rule (NDJSON) + {sum(1 for r in rows if r['id'])} ECS-compliant threat intel docs")

# ─── Microsoft Sentinel Analytics Rule (KQL) ───
def generate_sentinel(rows):
    all_ids = [r['id'] for r in rows if r['id']]
    chunk_size = 200
    chunks = [all_ids[i:i+chunk_size] for i in range(0, len(all_ids), chunk_size)]

    kql_parts = []
    for i, chunk in enumerate(chunks):
        ids_str = ", ".join(f'"{eid}"' for eid in chunk)
        kql_parts.append(f"let ExtSentryIDs_{i} = dynamic([{ids_str}]);")

    union_proc = " or ".join(f"ProcessCommandLine has_any (ExtSentryIDs_{i})" for i in range(len(chunks)))
    union_file = " or ".join(f"FolderPath has_any (ExtSentryIDs_{i})" for i in range(len(chunks)))
    union_reg = " or ".join(f"RegistryKey has_any (ExtSentryIDs_{i})" for i in range(len(chunks)))

    kql = "// ExtSentry - Browser Extension Threat Detection for Microsoft Sentinel\n"
    kql += f"// Source: https://github.com/mthcht/awesome-lists\n"
    kql += f"// Generated: {NOW}\n"
    kql += f"// Total extension IDs: {len(all_ids)} in {len(chunks)} chunks\n"
    kql += "//\n"
    kql += "// RECOMMENDATION: For production, import the IOC list as a Sentinel Watchlist\n"
    kql += "// and use _GetWatchlist('ExtSentry') instead of inline dynamic arrays.\n"
    kql += "// This avoids query size limits and simplifies updates.\n"
    kql += "//\n"
    kql += "// === QUERY 1: Process Command Line Detection ===\n"
    kql += "\n".join(kql_parts) + "\n"
    kql += f"""DeviceProcessEvents
| where {union_proc}
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| extend AlertInfo = "Suspicious browser extension detected by ExtSentry feed"
"""

    kql += "\n// === QUERY 2: File Event Detection (extension directories) ===\n"
    kql += "\n".join(kql_parts) + "\n"
    kql += f"""DeviceFileEvents
| where {union_file}
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    FolderPath,
    FileName,
    InitiatingProcessFileName
| extend AlertInfo = "Suspicious browser extension file activity detected by ExtSentry"
"""

    kql += "\n// === QUERY 3: Registry Event Detection ===\n"
    kql += "\n".join(kql_parts) + "\n"
    kql += f"""DeviceRegistryEvents
| where {union_reg}
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData
| extend AlertInfo = "Suspicious browser extension registry activity detected by ExtSentry"
"""

    with open(os.path.join(OUTPUT_DIR, "sentinel_analytics_rule.kql"), 'w') as f:
        f.write(kql)

    with open(os.path.join(OUTPUT_DIR, "sentinel_watchlist.csv"), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['ExtensionID', 'ExtensionName', 'Category', 'ThreatType', 'Severity', 'CrxSHA256', 'Reference'])
        w.writeheader()
        for row in rows:
            if not row['id']:
                continue
            w.writerow({
                'ExtensionID': row['id'],
                'ExtensionName': row['name'] or row['comment'] or '',
                'Category': row['category'],
                'ThreatType': row['type'],
                'Severity': SEVERITY_MAP.get(row['type'], 'medium'),
                'CrxSHA256': row['sha256'],
                'Reference': row['link']
            })

    print(f"  Microsoft Sentinel: KQL rules (3 tables) + Watchlist CSV, {len(all_ids)} IDs in {len(chunks)} chunks")


def main():
    print("ExtSentry Feed Generator v2 (Audited)")
    print("=" * 50)
    rows = load_csv()
    print(f"Loaded {len(rows)} entries from CSV\n")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Generating feeds...")
    generate_stix(rows)
    generate_misp(rows)
    generate_misp_warninglists(rows)
    generate_csv(rows)
    generate_json(rows)
    generate_splunk(rows)
    generate_sigma(rows)
    generate_openioc(rows)
    generate_yara(rows)
    generate_suricata(rows)
    generate_opencti_csv(rows)
    generate_plain_lists(rows)
    generate_elastic(rows)
    generate_sentinel(rows)

    print(f"\nAll feeds generated in {OUTPUT_DIR}")
    print("Files:")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        size = os.path.getsize(os.path.join(OUTPUT_DIR, f))
        print(f"  {f:55s} {size:>10,d} bytes")

if __name__ == "__main__":
    main()
