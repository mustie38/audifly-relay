"""Audifly "Birlikte Dinle" röle sunucusu.

Ses AKTARMAZ. Yalnızca aynı oda kodundaki istemciler arasında küçük JSON
mesajları (hangi şarkı, çalıyor mu, kaçıncı saniye) iletir. Her istemci şarkıyı
kendi bilgisayarında YouTube'dan çalar.

Çalıştırma:   python server.py            (PORT ortam değişkeni, varsayılan 8765)
Sağlık kontrolü: GET /health -> 200 (Render/Fly/Railway için)

Ters vekil (Reverse Proxy — Render / Fly.io / Nginx) yapılandırması:
- Varsayılan olarak doğrudan TCP bağlantı adresi (`ws.remote_address[0]`) kullanılır;
  istemcinin gönderdiği `X-Forwarded-For` başlığına koşulsuz güvenilmez.
- Sunucu güvenilir bir reverse proxy arkasında çalışıyorsa:
  * `TRUSTED_PROXIES="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1,::1"` (veya proxy IP'si)
  * ya da Render/Fly iç ağları için `TRUST_PROXY=1` ortam değişkenini tanımlayın.
"""
from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import time
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from websockets.asyncio.server import serve

log = logging.getLogger("relay")

PROTOCOL_VERSION = 2
MAX_SEQ = 2**31 - 1
MAX_ROOM_MEMBERS = 8
MAX_QUEUE = 50
MAX_CHAT_CHARS = 200
EMOJIS = {"❤️", "🔥", "👏", "😂", "😍", "🎉", "👍", "😭"}
MAX_MESSAGE_BYTES = 8192
MAX_BAD_JSON = 3
RATE_WINDOW_S = 10.0
RATE_MAX_MESSAGES = 40
CODE_RE = re.compile(r"^[A-Z0-9]{4,12}$")
MAX_ROOMS = int(os.environ.get("MAX_ROOMS", "500"))     # bellek tüketme saldırısına karşı üst sınır
FAIL_WINDOW_S = 300.0                                    # yanlış şifre denemeleri bu pencerede sayılır
FAIL_MAX = 8                                             # pencerede istemci başına izin verilen yanlış deneme
CONN_WINDOW_S = 10.0                                     # IP başına bağlantı hız sınırı penceresi
CONN_MAX = 25                                            # 10 sn içinde IP başına en fazla bağlantı
CREATE_WINDOW_S = 60.0                                   # IP başına oda oluşturma penceresi
CREATE_MAX = 10                                          # 60 sn içinde IP başına en fazla oda oluşturma
JOIN_WINDOW_S = 60.0                                     # IP başına odaya katılma penceresi
JOIN_MAX = 30                                            # 60 sn içinde IP başına en fazla katılma isteği
MAX_TRACKED_IPS = 4096                                   # IP tabloları için bellek üst sınırı

ALLOWED_SHARE_HOSTS = frozenset({
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "youtu.be",
})
ALLOWED_THUMBNAIL_HOSTS = frozenset({
    "i.ytimg.com",
    "i9.ytimg.com",
    "img.youtube.com",
    "lh3.googleusercontent.com",
    "yt3.ggpht.com",
})
_SONG_FIELDS = {"title": 200, "uploader": 120, "webpage_url": 300, "thumbnail": 400}

# Güvenilir proxy ağları: yalnızca TRUST_PROXY=1 veya TRUSTED_PROXIES tanımlandığında X-Forwarded-For okunur
_DEFAULT_PRIVATE_PROXIES = "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
TRUST_PROXY = os.environ.get("TRUST_PROXY", "").strip().lower() in ("1", "true", "yes")
TRUSTED_PROXIES_RAW = os.environ.get(
    "TRUSTED_PROXIES",
    _DEFAULT_PRIVATE_PROXIES if TRUST_PROXY else "",
)


class Member:
    def __init__(self, ws, name: str):
        self.id = secrets.token_hex(4)
        self.ws = ws
        self.name = name
        self.recent: list[float] = []
        self.last_seq: int = 0


class Room:
    def __init__(self, code: str):
        self.code = code
        self.members: dict[str, Member] = {}   # ekleme sırası = katılma sırası (ilk üye = sahip)
        self.state: dict | None = None
        self.queue: list[dict] = []            # ortak sıra
        self.pw_hash: str = ""                 # boşsa şifresiz oda (yalnız oluşturulurken belirlenir)
        self.state_at = 0.0

    @property
    def host_id(self) -> str:
        return next(iter(self.members), "")

    def members_payload(self) -> list[dict]:
        return [{"id": m.id, "name": m.name} for m in self.members.values()]


ROOMS: dict[str, Room] = {}
_FAILS: dict[str, list[float]] = {}          # istemci IP → yanlış şifre zamanları (monotonic)
_CONN_TIMES: dict[str, list[float]] = {}     # istemci IP → bağlantı zamanları
_CREATE_TIMES: dict[str, list[float]] = {}   # istemci IP → oda oluşturma zamanları
_JOIN_TIMES: dict[str, list[float]] = {}     # istemci IP → odaya katılma zamanları


def _parse_trusted_networks(spec: str) -> list:
    nets = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass
    return nets


def _is_trusted_proxy(ip_str: str, trusted_spec: str | None = None) -> bool:
    if not ip_str:
        return False
    spec = TRUSTED_PROXIES_RAW if trusted_spec is None else trusted_spec
    if not spec:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _parse_trusted_networks(spec))


def _normalize_ip(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def client_ip(ws, *, trusted_proxies: str | None = None) -> str:
    """Doğrudan bağlantı adresini döndürür; yalnızca doğrudan eş güvenilir bir proxy ise
    `X-Forwarded-For` başlığındaki son güvenilir-olmayan geçerli IP'yi kullanır."""
    peer_ip = ""
    try:
        peer_ip = _normalize_ip(str(ws.remote_address[0])) or str(ws.remote_address[0])
    except Exception:
        peer_ip = ""
    spec = TRUSTED_PROXIES_RAW if trusted_proxies is None else trusted_proxies
    if peer_ip and _is_trusted_proxy(peer_ip, spec):
        try:
            forwarded = ws.request.headers.get("X-Forwarded-For", "")
            hops = [_normalize_ip(part) for part in forwarded.split(",")]
            valid_hops = [h for h in hops if h]
            if valid_hops:
                for hop in reversed(valid_hops):
                    if not _is_trusted_proxy(hop, spec):
                        return hop
                return valid_hops[0]
        except Exception:
            pass
    return peer_ip


def _prune_ip_store(store: dict[str, list[float]], ip: str, window: float, now: float) -> list[float]:
    recent = [t for t in store.get(ip, []) if now - t < window]
    if recent:
        store[ip] = recent
    else:
        store.pop(ip, None)
    if len(store) > MAX_TRACKED_IPS:
        for k in list(store.keys()):
            kept = [t for t in store[k] if now - t < window]
            if kept:
                store[k] = kept
            else:
                store.pop(k, None)
        while len(store) > MAX_TRACKED_IPS:
            oldest_key = min(store, key=lambda k: store[k][-1] if store[k] else 0.0)
            store.pop(oldest_key, None)
    return recent


def too_many_failures(ip: str, now: float | None = None) -> bool:
    if not ip:
        return False
    now = time.monotonic() if now is None else now
    recent = _prune_ip_store(_FAILS, ip, FAIL_WINDOW_S, now)
    return len(recent) >= FAIL_MAX


def record_failure(ip: str, now: float | None = None) -> None:
    if not ip:
        return
    now = time.monotonic() if now is None else now
    recent = _prune_ip_store(_FAILS, ip, FAIL_WINDOW_S, now)
    recent.append(now)
    _FAILS[ip] = recent


def _check_ip_rate_limit(store: dict[str, list[float]], ip: str, window: float,
                         limit: int, now: float | None = None) -> bool:
    if not ip:
        return False
    now = time.monotonic() if now is None else now
    recent = _prune_ip_store(store, ip, window, now)
    if len(recent) >= limit:
        return True
    recent.append(now)
    store[ip] = recent
    return False


def conn_rate_limited(ip: str, now: float | None = None) -> bool:
    return _check_ip_rate_limit(_CONN_TIMES, ip, CONN_WINDOW_S, CONN_MAX, now)


def request_rate_limited(ip: str, kind: str, now: float | None = None) -> bool:
    if kind == "create":
        return _check_ip_rate_limit(_CREATE_TIMES, ip, CREATE_WINDOW_S, CREATE_MAX, now)
    return _check_ip_rate_limit(_JOIN_TIMES, ip, JOIN_WINDOW_S, JOIN_MAX, now)


def clear_rate_limits() -> None:
    """Testler için tüm IP sayaçlarını temizler."""
    _FAILS.clear()
    _CONN_TIMES.clear()
    _CREATE_TIMES.clear()
    _JOIN_TIMES.clear()


def clean_name(raw) -> str:
    name = re.sub(r"\s+", " ", str(raw or "")).strip()[:24]
    return name or "Misafir"


def is_valid_share_url(url) -> bool:
    """Birlikte Dinle üzerinden paylaşılabilecek müzik bağlantısını doğrular.

    Yalnızca HTTPS şemalı, kimlik bilgisi/beklenmeyen port içermeyen, izin verilen
    YouTube / YouTube Music alan adlarına ait geçerli parça adresleri kabul edilir.
    """
    if not isinstance(url, str):
        return False
    url = url.strip()
    if not (1 <= len(url) <= 300) or any(ord(c) <= 32 for c in url):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if (parts.scheme or "").lower() != "https":
        return False
    if parts.username is not None or parts.password is not None or "@" in (parts.netloc or ""):
        return False
    if port not in (None, 443):
        return False
    host = (parts.hostname or "").lower().rstrip(".")
    if host not in ALLOWED_SHARE_HOSTS:
        return False
    path = parts.path or ""
    if not path or path == "/" or ".." in path or "\\" in path:
        return False
    if host == "youtu.be":
        vid = path.lstrip("/").split("/", 1)[0]
        return bool(vid) and all(ch.isalnum() or ch in "-_" for ch in vid)
    if path == "/watch":
        qs = parse_qs(parts.query)
        v = (qs.get("v") or [""])[0]
        return bool(v) and all(ch.isalnum() or ch in "-_" for ch in v)
    if path.startswith(("/shorts/", "/live/", "/embed/")):
        seg = path.split("/", 2)[2].split("/", 1)[0] if path.count("/") >= 2 else ""
        return bool(seg) and all(ch.isalnum() or ch in "-_" for ch in seg)
    if path == "/playlist":
        qs = parse_qs(parts.query)
        plist = (qs.get("list") or [""])[0]
        return bool(plist) and all(ch.isalnum() or ch in "-_" for ch in plist)
    return False


def is_valid_thumbnail_url(url) -> bool:
    if not isinstance(url, str) or not (1 <= len(url) <= 400) or any(ord(c) <= 32 for c in url):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if (parts.scheme or "").lower() != "https":
        return False
    if parts.username is not None or parts.password is not None or "@" in (parts.netloc or ""):
        return False
    if port not in (None, 443):
        return False
    host = (parts.hostname or "").lower().rstrip(".")
    return host in ALLOWED_THUMBNAIL_HOSTS and ".." not in (parts.path or "")


def clean_song(raw) -> dict | None:
    if not isinstance(raw, dict) or raw.get("local_path"):
        return None
    out: dict = {}
    for key, limit in _SONG_FIELDS.items():
        value = raw.get(key)
        if isinstance(value, str):
            out[key] = value[:limit]
    url = out.get("webpage_url", "").strip()
    if not is_valid_share_url(url):
        return None
    out["webpage_url"] = url
    if "thumbnail" in out and not is_valid_thumbnail_url(out["thumbnail"]):
        out.pop("thumbnail", None)
    duration = raw.get("duration")
    if isinstance(duration, (int, float)) and not isinstance(duration, bool) and 0 <= duration < 86400:
        out["duration"] = int(duration)
    return out


def _clean_ms(value, limit: int) -> int:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0, min(int(value), limit))
    return 0


def clean_pw(raw) -> str:
    """İstemci SHA-256 özeti yollar (64 hex); düz şifre sunucuya hiç gelmez."""
    value = str(raw or "")
    return value if re.fullmatch(r"[0-9a-f]{64}", value) else ""


def is_valid_seq(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_SEQ


def clean_state(raw: dict, last_seq: int = 0) -> dict | None:
    if not isinstance(raw, dict):
        return None
    song = clean_song(raw.get("song"))
    if song is None:
        return None
    seq, pos = raw.get("seq"), raw.get("pos_ms")
    if not is_valid_seq(seq) or seq <= last_seq:
        return None
    if not isinstance(pos, (int, float)) or isinstance(pos, bool):
        return None
    return {
        "t": "state", "seq": seq, "song": song,
        "playing": bool(raw.get("playing")),
        "pos_ms": max(0, min(int(pos), 86_400_000)),
        "hb": bool(raw.get("hb")),
        "sync": bool(raw.get("sync")),
        "lat": _clean_ms(raw.get("lat"), 5000),
    }


async def send(ws, payload: dict):
    try:
        await ws.send(json.dumps(payload, ensure_ascii=False))
    except Exception:
        pass   # kopan bağlantı kendi handler'ında temizlenir


async def broadcast(room: Room, payload: dict, skip: str | None = None):
    await asyncio.gather(*(send(m.ws, payload) for mid, m in room.members.items() if mid != skip))


def rate_limited(member: Member) -> bool:
    now = time.monotonic()
    member.recent = [t for t in member.recent if now - t < RATE_WINDOW_S]
    if len(member.recent) >= RATE_MAX_MESSAGES:
        return True
    member.recent.append(now)
    return False


async def handler(ws):
    member: Member | None = None
    room: Room | None = None
    ip = client_ip(ws)
    if conn_rate_limited(ip):
        await send(ws, {"t": "error", "code": "rate_limited",
                        "msg": "Çok fazla bağlantı isteği. Lütfen biraz bekle."})
        return
    bad_json_count = 0
    try:
        async for raw in ws:
            raw_bytes = raw.encode("utf-8", "replace") if isinstance(raw, str) else bytes(raw)
            if len(raw_bytes) > MAX_MESSAGE_BYTES:
                await send(ws, {"t": "error", "code": "message_too_large",
                                "msg": "Mesaj boyutu sınırı aşıldı."})
                return
            try:
                msg = json.loads(raw)
                if not isinstance(msg, dict):
                    raise ValueError
            except ValueError:
                bad_json_count += 1
                if member is None or bad_json_count >= MAX_BAD_JSON:
                    await send(ws, {"t": "error", "code": "invalid_json",
                                    "msg": "Geçersiz mesaj biçimi."})
                    return
                continue
            kind = msg.get("t")

            if member is None:
                if kind not in ("create", "join"):
                    await send(ws, {"t": "error", "code": "not_joined",
                                    "msg": "Önce odaya katılmalısın."})
                    return
                action = "create" if (kind == "create" or msg.get("mode") == "create") else "join"
                if msg.get("v") != PROTOCOL_VERSION:
                    await send(ws, {"t": "error", "code": "version_mismatch",
                                    "msg": "Uygulama sürümü sunucuyla uyumsuz."})
                    return
                if request_rate_limited(ip, action):
                    await send(ws, {"t": "error", "code": "rate_limited",
                                    "msg": "Çok fazla oda isteği. Lütfen biraz bekle."})
                    return
                code = str(msg.get("room", "")).upper()
                if not CODE_RE.match(code):
                    await send(ws, {"t": "error", "code": "invalid_room_code",
                                    "msg": "Oda kodu 4-12 harf/rakam olmalı."})
                    return
                pw = clean_pw(msg.get("pw"))
                existing = ROOMS.get(code)
                if action == "create":
                    if existing is not None:
                        await send(ws, {"t": "error", "code": "room_exists",
                                        "msg": "Bu oda kodu zaten kullanımda."})
                        return
                    if len(ROOMS) >= MAX_ROOMS:
                        await send(ws, {"t": "error", "code": "server_full",
                                        "msg": "Sunucu şu an çok dolu, biraz sonra tekrar dene."})
                        return
                    room = ROOMS[code] = Room(code)
                    room.pw_hash = pw                 # şifre yalnızca oda oluşturulurken belirlenir
                else:
                    if existing is None:
                        await send(ws, {"t": "error", "code": "room_not_found",
                                        "msg": "Oda bulunamadı."})
                        return
                    room = existing
                    if room.pw_hash:
                        if too_many_failures(ip):
                            await send(ws, {"t": "error", "code": "too_many_attempts",
                                            "msg": "Çok fazla yanlış deneme. Birkaç dakika sonra tekrar dene."})
                            room = None
                            return
                        if not hmac.compare_digest(room.pw_hash, pw):
                            record_failure(ip)
                            await send(ws, {"t": "error", "code": "wrong_password",
                                            "msg": "Oda şifresi yanlış."})
                            room = None
                            return
                if len(room.members) >= MAX_ROOM_MEMBERS:
                    await send(ws, {"t": "error", "code": "room_full", "msg": "Oda dolu."})
                    room = None
                    return
                member = Member(ws, clean_name(msg.get("name")))
                room.members[member.id] = member
                state = None
                if room.state is not None:
                    sender_id = room.state.get("from") or room.host_id
                    state = {**room.state, "from": sender_id,
                             "age_ms": int((time.monotonic() - room.state_at) * 1000)}
                await send(ws, {"t": "joined", "id": member.id, "host": room.host_id,
                                "members": room.members_payload(), "state": state,
                                "queue": room.queue, "locked": bool(room.pw_hash)})
                await broadcast(room, {"t": "members", "host": room.host_id,
                                       "members": room.members_payload()}, skip=member.id)
                log.info("%s odaya katıldı (%s), üye sayısı: %d", member.name, code, len(room.members))
                continue

            if rate_limited(member):
                continue
            if kind == "state":
                state = clean_state(msg, last_seq=member.last_seq)
                if state is None:
                    continue
                member.last_seq = state["seq"]
                room.state, room.state_at = dict(state, **{"from": member.id}), time.monotonic()
                await broadcast(room, {**state, "from": member.id, "age_ms": 0}, skip=member.id)
            elif kind == "ping":
                echo = msg.get("c")
                await send(ws, {"t": "pong", "c": echo if isinstance(echo, (int, float))
                                and not isinstance(echo, bool) else 0})
            elif kind == "transfer":
                # Yalnız oda sahibi sahipliği devredebilir: hedef üye listenin başına geçer.
                target = str(msg.get("to", ""))
                if member.id == room.host_id and target in room.members and target != member.id:
                    room.members = {target: room.members[target],
                                    **{k: v for k, v in room.members.items() if k != target}}
                    await broadcast(room, {"t": "members", "host": room.host_id,
                                           "members": room.members_payload()})
            elif kind == "sync_req":
                host = room.members.get(room.host_id)
                if host is not None and host.id != member.id:
                    await send(host.ws, {"t": "sync_req", "from": member.id})
            elif kind == "chat":
                text = re.sub(r"\s+", " ", str(msg.get("text", ""))).strip()[:MAX_CHAT_CHARS]
                if text:
                    await broadcast(room, {"t": "chat", "from": member.id,
                                           "name": member.name, "text": text}, skip=member.id)
            elif kind == "emoji":
                if msg.get("e") in EMOJIS:
                    await broadcast(room, {"t": "emoji", "from": member.id,
                                           "name": member.name, "e": msg["e"]}, skip=member.id)
            elif kind == "queue_add":
                song = clean_song(msg.get("song"))
                if song is not None and len(room.queue) < MAX_QUEUE:
                    room.queue.append({**song, "by": member.name})
                    await broadcast(room, {"t": "queue", "items": room.queue})
            elif kind == "queue_remove":
                url = str(msg.get("url", ""))
                for i, item in enumerate(room.queue):
                    if item.get("webpage_url") == url:
                        del room.queue[i]
                        await broadcast(room, {"t": "queue", "items": room.queue})
                        break
            elif kind == "queue_pop":
                # Yalnız baştaki şarkı çalınmak üzere alınmışsa düşer (çift istek zararsız)
                if room.queue and room.queue[0].get("webpage_url") == str(msg.get("url", "")):
                    room.queue.pop(0)
                    await broadcast(room, {"t": "queue", "items": room.queue})
    finally:
        if member is not None and room is not None:
            room.members.pop(member.id, None)
            if not room.members:
                ROOMS.pop(room.code, None)
            else:
                await broadcast(room, {"t": "members", "host": room.host_id,
                                       "members": room.members_payload()})
            log.info("%s ayrıldı (%s)", member.name, room.code)


def process_request(connection, request):
    """Düz HTTP istekleri (sağlık kontrolü) için; WebSocket yükseltmeleri geçer."""
    if request.headers.get("Upgrade", "").lower() != "websocket":
        if request.path in ("/", "/health"):
            return connection.respond(HTTPStatus.OK, "Audifly relay OK\n")
        return connection.respond(HTTPStatus.NOT_FOUND, "Not found\n")
    return None


async def run(host: str = "0.0.0.0", port: int = 8765):
    async with serve(handler, host, port, process_request=process_request,
                     max_size=MAX_MESSAGE_BYTES, ping_interval=20, ping_timeout=20):
        log.info("Röle sunucusu %s:%d üzerinde dinliyor", host, port)
        await asyncio.Future()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    asyncio.run(run(port=int(os.environ.get("PORT", "8765"))))

