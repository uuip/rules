from pathlib import Path

import yaml

key_list = [
    "DOMAIN-KEYWORD",
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
]


def filter_key(x):
    return x.split(",")[0] in key_list


for f in Path(".").glob("*.yaml"):
    f_io = f.open(encoding="utf8")
    clash = yaml.safe_load(f_io)
    f_io.close()
    step1 = filter(lambda x: x and not x.startswith("PROCESS-NAME"), clash["payload"])
    step2 = filter(filter_key, step1)
    step3 = map(lambda x: f"{x}\n", step2)

    with open("loon" / f.with_suffix(".list"), "w+", encoding="utf8", newline="\n") as qx:
        qx.writelines(step3)
