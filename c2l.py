from pathlib import Path

import yaml

key_list = [
    "DOMAIN-KEYWORD",
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
]

rule_files = []

for f in Path(".").glob("*.yaml"):
    if f.name == "censor_dns.yaml":
        continue
    name_parts = f.stem.split("-", 2)
    if len(name_parts) < 2 or not name_parts[0].isdigit():
        raise ValueError(f"Invalid rule filename: {f.name}")
    rule_files.append((int(name_parts[0]), f.name, f))

for _, _, f in sorted(rule_files):
    f_io = f.open(encoding="utf8")
    clash = yaml.safe_load(f_io)
    f_io.close()

    toadd = []

    for line in clash["payload"]:
        parts = list(map(lambda s: s.strip(), line.split(",")))
        if parts[0] == "DOMAIN-WILDCARD":
            pattern = parts[1]
            if not pattern.startswith("*") or pattern.count("*") != 2 or "*." not in pattern:
                raise ValueError(f"Unsupported DOMAIN-WILDCARD pattern: {pattern}")
            keyword, suffix = pattern[1:].split("*.", 1)
            toadd.append(
                f"AND,((DOMAIN-KEYWORD,{keyword}),(DOMAIN-SUFFIX,{suffix}))\n"
            )
        elif parts[0] in key_list:
            toadd.append(",".join(parts) + "\n")

    with open("loon" / f.with_suffix(".list"), "w+", encoding="utf8", newline="\n") as qx:
        qx.writelines(toadd)
