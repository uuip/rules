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

for f in Path(".").glob("*.yaml"):
    f_io = f.open(encoding="utf8")
    clash = yaml.safe_load(f_io)
    f_io.close()

    toadd = []

    for line in clash["payload"]:
        parts = list(map(lambda s: s.strip(), line.split(",")))
        if parts[0] in key_map:
            parts[0] = key_map[parts[0]]
            parts.append(f.stem)
        if "no-resolve" in parts:
            parts.remove("no-resolve")
            parts.append("no-resolve")
        toadd.append(",".join(parts).lower() + "\n")

    with open("qx" / f.with_suffix(".list"), "w+", encoding="utf8", newline="\n") as qx:
        qx.writelines(toadd)
