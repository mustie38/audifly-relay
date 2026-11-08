"""Audifly "Birlikte Dinle" röle sunucusu.

Ses AKTARMAZ. Yalnızca aynı oda kodundaki istemciler arasında küçük JSON
mesajları (hangi şarkı, çalıyor mu, kaçıncı saniye) iletir. Her istemci şarkıyı
kendi bilgisayarında YouTube'dan çalar.

Çalıştırma:   python server.py            (PORT ortam değişkeni, varsayılan 8765)
Sağlık kontrolü: GET /health -> 200 (Render/Fly/Railway için)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import time
from http import HTTPStatus

from websockets.asyncio.server import serve

log = logging.getLogger("relay")

PROTOCOL_VERSION = 1
MAX_ROOM_MEMBERS = 8
MAX_MESSAGE_BYTES = 8192
RATE_WINDOW_S = 10.0
RATE_MAX_MESSAGES = 40
CODE_RE = re.compile(r"^[A-Z0-9]{4,12}$")
_SONG_FIELDS = {"title": 200, "uploader": 120, "webpage_url": 300, "thumbnail": 400}


class Member:
    def __init__(self, ws, name: str):
        self.id = secrets.token_hex(4)
        self.ws = ws
        self.name = name
        self.recent: list[float] = []


class Room:
    def __init__(self, code: str):
        self.code = code
        self.members: dict[str, Member] = {}   # ekleme sırası = katılma sırası (ilk üye = sahip)
        self.state: dict | None = None
        self.state_at = 0.0

    @property
    def host_id(self) -> str:
        return next(iter(self.members), "")

    def members_payload(self) -> list[dict]:
        return [{"id": m.id, "name": m.name} for m in self.members.values()]


ROOMS: dict[str, Room] = {}


def clean_name(raw) -> str:
    name = re.sub(r"\s+", " ", str(raw or "")).strip()[:24]
    return name or "Misafir"


def clean_song(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    out: dict = {}
    for key, limit in _SONG_FIELDS.items():
        value = raw.get(key)
        if isinstance(value, str):
            out[key] = value[:limit]
    url = out.get("webpage_url", "")
    if not url.startswith(("http://", "https://")):
        return None
    duration = raw.get("duration")
    if isinstance(duration, (int, float)) and not isinstance(duration, bool) and 0 <= duration < 86400:
        out["duration"] = int(duration)
    return out


def clean_state(raw: dict) -> dict | None:
    song = clean_song(raw.get("song"))
    if song is None:
        return None
    seq, pos = raw.get("seq"), raw.get("pos_ms")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0 or seq > 2**31:
        return None
    if not isinstance(pos, (int, float)) or isinstance(pos, bool):
        return None
    return {
        "t": "state", "seq": seq, "song": song,
        "playing": bool(raw.get("playing")),
        "pos_ms": max(0, min(int(pos), 86_400_000)),
        "hb": bool(raw.get("hb")),
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
    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
                if not isinstance(msg, dict):
                    raise ValueError
            except ValueError:
                continue
            kind = msg.get("t")

            if member is None:
                if kind != "join":
                    await send(ws, {"t": "error", "msg": "Önce odaya katılmalısın."})
                    return
                code = str(msg.get("room", "")).upper()
                if msg.get("v") != PROTOCOL_VERSION:
                    await send(ws, {"t": "error", "msg": "Uygulama sürümü sunucuyla uyumsuz."})
                    return
                if not CODE_RE.match(code):
                    await send(ws, {"t": "error", "msg": "Oda kodu 4-12 harf/rakam olmalı."})
                    return
                room = ROOMS.setdefault(code, Room(code))
                if len(room.members) >= MAX_ROOM_MEMBERS:
                    await send(ws, {"t": "error", "msg": "Oda dolu."})
                    room = None
                    return
                member = Member(ws, clean_name(msg.get("name")))
                room.members[member.id] = member
                state = None
                if room.state is not None:
                    state = {**room.state, "from": room.host_id,
                             "age_ms": int((time.monotonic() - room.state_at) * 1000)}
                await send(ws, {"t": "joined", "id": member.id, "host": room.host_id,
                                "members": room.members_payload(), "state": state})
                await broadcast(room, {"t": "members", "host": room.host_id,
                                       "members": room.members_payload()}, skip=member.id)
                log.info("%s odaya katıldı (%s), üye sayısı: %d", member.name, code, len(room.members))
                continue

            if rate_limited(member):
                continue
            if kind == "state":
                state = clean_state(msg)
                if state is None:
                    continue
                room.state, room.state_at = state, time.monotonic()
                room.state["from"] = member.id
                await broadcast(room, {**state, "from": member.id, "age_ms": 0}, skip=member.id)
            elif kind == "ping":
                await send(ws, {"t": "pong"})
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
