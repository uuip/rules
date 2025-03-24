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

for f in Path(".").glob("*.yaml"):
    f_io = f.open(encoding="utf8")
    clash = yaml.safe_load(f_io)
    f_io.close()

    toadd = []

    for line in clash["payload"]:
        parts = list(map(lambda s: s.strip(), line.split(",")))
        if parts[0] in key_list:
            toadd.append(",".join(parts) + "\n")

    with open("loon" / f.with_suffix(".list"), "w+", encoding="utf8", newline="\n") as qx:
        qx.writelines(toadd)
