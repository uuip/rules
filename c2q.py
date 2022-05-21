import re
from pathlib import Path

import yaml

key_map = {"DOMAIN-KEYWORD": "host-keyword",
           "DOMAIN": "host",
           "DOMAIN-SUFFIX": "host-suffix",
           "IP-CIDR": "ip-cidr",
           "IP-CIDR6": "ip6-cidr",
           "GEOIP": "geoip"

           }
policy = {"d": "direct",
          "r": "reject",
          "p": "proxy",
          "tg": "Telegram"
          }

pattern = re.compile(f'({"|".join(x for x in key_map)})(?=\s*?,)')
drop_pattern = re.compile(',\s*no-resolve')


def subrepl(matchobj):
    return key_map.get(matchobj.group(1))


def wrap_sub(string):
    return pattern.sub(subrepl, string)


def wrap_drop(string):
    return drop_pattern.sub('', string)


for f in Path('.').glob('*.yaml'):
    f_io = f.open(encoding='utf8')
    clash = yaml.safe_load(f_io.read())
    f_io.close()
    step1 = filter(lambda x: not x.startswith("PROCESS-NAME"), clash["payload"])
    step2 = map(wrap_sub, step1)
    step3 = map(wrap_drop, step2)
    step4 = map(lambda x: f'{x},{policy.get(f.stem)}\n'.lower(), step3)

    with open("qx" / f.with_suffix('.list'), 'w+', encoding='utf8') as qx:
        qx.writelines(step4)
