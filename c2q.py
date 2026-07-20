from pathlib import Path

import yaml

key_map = {
    "DOMAIN-KEYWORD": "host-keyword",
    "DOMAIN": "host",
    "DOMAIN-SUFFIX": "host-suffix",
    "IP-CIDR": "ip-cidr",
    "IP-CIDR6": "ip6-cidr",
    "GEOIP": "geoip",
    "IP-ASN": "ip-asn",
}

rule_files = []

for f in Path(".").glob("*.yaml"):
    if f.name == "censor_dns.yaml":
        continue
    name_parts = f.stem.split("-", 2)
    if len(name_parts) < 2 or not name_parts[0].isdigit():
        raise ValueError(f"Invalid rule filename: {f.name}")
    rule_files.append((int(name_parts[0]), f.name, name_parts[1], f))

for _, _, action, f in sorted(rule_files):
    f_io = f.open(encoding="utf8")
    clash = yaml.safe_load(f_io)
    f_io.close()

    toadd = []

    for line in clash["payload"]:
        parts = list(map(lambda s: s.strip(), line.split(",")))
        if parts[0] in key_map:
            parts[0] = key_map[parts[0]]
            parts.append(action)
        if "no-resolve" in parts:
            parts.remove("no-resolve")
            parts.append("no-resolve")
        toadd.append(",".join(parts).lower() + "\n")

    with open("qx" / f.with_suffix(".list"), "w+", encoding="utf8", newline="\n") as qx:
        qx.writelines(toadd)
