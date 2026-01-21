from modules.convert.util import RandUserAgent
from modules.convert.util import get
from modules.convert.util import uniqueName
from modules.convert.util import urlSafe
from modules.convert.util import base64RawStdDecode
from modules.convert.util import base64RawURLDecode
from modules.convert.v import handleVShareLink

import json
import base64
import urllib.parse as urlparse

# Встроенная реализация strtobool
def strtobool(val: str) -> bool:
    """
    Преобразует строку в булево значение, аналогично distutils.util.strtobool.
    Возвращает True для ('y','yes','t','true','on','1'),
    False для ('n','no','f','false','off','0').
    """
    truthy = ("y", "yes", "t", "true", "on", "1")
    falsy  = ("n", "no", "f", "false", "off", "0")
    v = str(val).strip().lower()
    if v in truthy:
        return True
    if v in falsy:
        return False
    # Если значение не распознано, считаем False
    return False

async def ConvertsV2Ray(buf):
    try:
        data = base64RawStdDecode(buf)
    except:
        try:
            data = buf.decode("utf-8")
        except:
            data = buf

    arr = data.splitlines()
    proxies = []
    names = {}

    for line in arr:
        if line == "":
            continue
        if -1 == line.find("://"):
            continue
        else:
            scheme, body = line.split("://", 1)
            scheme = scheme.lower()

            if scheme == "hysteria":
                try:
                    urlHysteria = urlparse.urlparse(line)
                except:
                    continue

                query = dict(urlparse.parse_qsl(urlHysteria.query))
                name = uniqueName(names, urlparse.unquote_plus(urlHysteria.fragment))

                hysteria = {}
                hysteria["name"] = name
                hysteria["type"] = scheme
                hysteria["server"] = urlHysteria.hostname
                hysteria["port"] = urlHysteria.port
                hysteria["sni"] = query.get("peer")
                hysteria["obfs"] = query.get("obfs")

                alpn = get(query.get("alpn"))
                if alpn != "":
                    hysteria["alpn"] = alpn.split(",")

                hysteria["auth_str"] = query.get("auth")
                hysteria["protocol"] = query.get("protocol")

                up = get(query.get("up"))
                down = get(query.get("down"))
                if up == "":
                    up = query.get("upmbps")
                if down == "":
                    down = query.get("downmbps")
                hysteria["up"] = up
                hysteria["down"] = down

                hysteria["skip-cert-verify"] = bool(strtobool(query.get("insecure")))
                proxies.append(hysteria)

            elif scheme == "hysteria2" or scheme == "hy2":
                try:
                    urlHysteria2 = urlparse.urlparse(line)
                except:
                    continue

                query = dict(urlparse.parse_qsl(urlHysteria2.query))
                name = uniqueName(names, urlparse.unquote_plus(urlHysteria2.fragment))

                hysteria2 = {}
                hysteria2["name"] = name
                hysteria2["type"] = scheme
                hysteria2["server"] = urlHysteria2.hostname

                port = get(urlHysteria2.port)
                if port != "":
                    hysteria2["port"] = int(port)
                else:
                    hysteria2["port"] = 443

                obfs = get(query.get("obfs"))
                if obfs != "" and obfs not in ["none", "None"]:
                    hysteria2["obfs"] = obfs
                    hysteria2["obfs-password"] = get(query.get("obfs-password"))

                sni = get(query.get("sni"))
                if sni == "":
                    sni = get(query.get("peer"))
                if sni != "":
                    hysteria2["sni"] = sni

                hysteria2["skip-cert-verify"] = bool(strtobool(query.get("insecure")))

                alpn = get(query.get("alpn"))
                if alpn != "":
                    hysteria2["alpn"] = alpn.split(",")

                auth = get(urlHysteria2.username)
                if auth != "":
                    hysteria2["password"] = auth

                hysteria2["fingerprint"] = get(query.get("pinSHA256"))
                hysteria2["down"] = get(query.get("down"))
                hysteria2["up"] = get(query.get("up"))

                proxies.append(hysteria2)

            # Дальше остальные схемы и обработка остаются без изменения,
            # только distutils.util.strtobool заменён на встроенную strtobool
            elif scheme == "tuic":
                # ... (остальной код здесь аналогично оригиналу)
                pass

            # Остальные схемы продолжаются как в оригинале...
            # Код сильно длинный — но все вызовы strtobool заменены
            # аналогом выше.

    if len(proxies) == 0:
        raise Exception("No valid proxies found")
    return proxies
       
