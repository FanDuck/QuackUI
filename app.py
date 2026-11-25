#!/usr/bin/env python3
"""
QuackUI v2.0.0 - Lightweight, Local-First Xray Management Panel by FanDuck
Zero third-party Python dependencies. Pure Python 3 stdlib + SQLite3.
Listens on 127.0.0.1 by default (accessed via SSH tunnel).
"""

import datetime
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tarfile
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote_plus

VERSION = "2.0.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
CFG_PATH = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "quackui.db")
XRAY_CFG = "/usr/local/etc/xray/config.json"
NFT_CFG = "/etc/nftables.conf"
NODE_INFO = "/root/node-info.txt"
CUSTOM_V6_IFACE = "/etc/network/interfaces.d/60-custom-v6"

SESSIONS = {}        # token -> expire_ts
LOGIN_FAILS = {}     # ip -> [count, block_until]
DB_LOCK = threading.Lock()
TRAFFIC_LOCK = threading.Lock()
PREV_COUNTERS = {}   # tag -> (up, down)
RATES = {"up": 0.0, "down": 0.0, "ts": 0.0}


def load_cfg():
    with open(CFG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_cfg(cfg):
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(CFG_PATH, 0o600)


def hash_password(password, salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 100000
    ).hex()


def run_cmd(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


def db_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with DB_LOCK, db_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS daily_traffic (
                date TEXT NOT NULL,
                tag TEXT NOT NULL,
                uplink INTEGER NOT NULL DEFAULT 0,
                downlink INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (date, tag)
            );
            CREATE TABLE IF NOT EXISTS node_meta (
                tag TEXT PRIMARY KEY,
                remark TEXT NOT NULL DEFAULT '',
                public_key TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                disabled_json TEXT NOT NULL DEFAULT ''
            );
        """)
    if os.path.exists(DB_PATH):
        os.chmod(DB_PATH, 0o600)

    # Seed existing reality-in metadata from /root/node-info.txt if not present
    info = read_node_info()
    if info.get("REALITY_PUB"):
        with DB_LOCK, db_conn() as conn:
            row = conn.execute("SELECT tag FROM node_meta WHERE tag='reality-in'").fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO node_meta(tag, remark, public_key, enabled) VALUES(?,?,?,1)",
                    ("reality-in", "QuackUI-Reality-v6", info["REALITY_PUB"]),
                )


def read_node_info():
    info = {}
    if os.path.exists(NODE_INFO):
        with open(NODE_INFO, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip()
    return info


def write_node_info(info):
    with open(NODE_INFO, "w", encoding="utf-8") as f:
        f.write("\n".join(f"{k}={v}" for k, v in info.items()) + "\n")
    os.chmod(NODE_INFO, 0o600)


def read_xray_cfg():
    with open(XRAY_CFG, "r", encoding="utf-8") as f:
        return json.load(f)


def save_xray_cfg(cfg):
    tmp = XRAY_CFG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    code, _, err = run_cmd(["xray", "run", "-test", "-c", tmp])
    if code != 0:
        os.remove(tmp)
        raise RuntimeError(f"Xray 配置校验失败: {err}")
    shutil.move(tmp, XRAY_CFG)
    code, _, err = run_cmd(["systemctl", "restart", "xray"])
    if code != 0:
        raise RuntimeError(f"重启 Xray 失败: {err}")


def detect_default_v6_iface_and_prefix():
    code, out, _ = run_cmd(["ip", "-6", "route", "show", "default"], timeout=4)
    iface = "eth0"
    if code == 0 and out:
        m = re.search(r"dev\s+(\S+)", out)
        if m:
            iface = m.group(1)
    code, out, _ = run_cmd(["ip", "-6", "addr", "show", "dev", iface, "scope", "global"], timeout=4)
    addrs = re.findall(r"inet6\s+([0-9a-fA-F:]+)/(\d+)", out or "")
    if not addrs:
        raise RuntimeError(f"未在网卡 {iface} 上检测到全局 IPv6 地址")
    addr, plen = addrs[0]
    net = ipaddress.IPv6Interface(f"{addr}/{plen}").network
    prefix_4groups = ":".join(net.network_address.exploded.split(":")[:4])
    return iface, prefix_4groups, int(plen), addr


def detect_public_ipv4():
    code, out, _ = run_cmd(["ip", "-4", "route", "get", "1.1.1.1"], timeout=3)
    if code == 0 and out:
        m = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    return "127.0.0.1"


def generate_x25519():
    code, out, err = run_cmd(["xray", "x25519"])
    if code != 0:
        raise RuntimeError(f"生成 x25519 密钥失败: {err}")
    priv = pub = ""
    for line in out.splitlines():
        if "PrivateKey:" in line or "Private key:" in line:
            priv = line.split(":", 1)[1].strip()
        elif "PublicKey" in line or "Public key:" in line or "Password:" in line:
            pub = line.split(":", 1)[1].strip()
    if not priv or not pub:
        raise RuntimeError("解析 x25519 输出失败")
    return priv, pub


def get_meta_map():
    with DB_LOCK, db_conn() as conn:
        rows = conn.execute("SELECT * FROM node_meta").fetchall()
        return {r["tag"]: dict(r) for r in rows}


def set_meta(tag, remark=None, public_key=None, enabled=None, disabled_json=None):
    with DB_LOCK, db_conn() as conn:
        cur = conn.execute("SELECT * FROM node_meta WHERE tag=?", (tag,)).fetchone()
        if not cur:
            conn.execute(
                "INSERT INTO node_meta(tag, remark, public_key, enabled, disabled_json) VALUES(?,?,?,?,?)",
                (
                    tag,
                    remark if remark is not None else tag,
                    public_key if public_key is not None else "",
                    1 if enabled is None else int(enabled),
                    disabled_json if disabled_json is not None else "",
                ),
            )
        else:
            conn.execute(
                "UPDATE node_meta SET remark=?, public_key=?, enabled=?, disabled_json=? WHERE tag=?",
                (
                    remark if remark is not None else cur["remark"],
                    public_key if public_key is not None else cur["public_key"],
                    int(enabled) if enabled is not None else cur["enabled"],
                    disabled_json if disabled_json is not None else cur["disabled_json"],
                    tag,
                ),
            )


def del_meta(tag):
    with DB_LOCK, db_conn() as conn:
        conn.execute("DELETE FROM node_meta WHERE tag=?", (tag,))


def sample_xray_traffic():
    """Poll Xray Stats API and persist deltas into SQLite."""
    code, out, _ = run_cmd(["xray", "api", "statsquery", "--server=127.0.0.1:10085"], timeout=4)
    if code != 0 or not out:
        return
    try:
        data = json.loads(out)
    except Exception:
        return

    cur_map = {}  # tag -> [up, down]
    for item in data.get("stat", []):
        name = item.get("name", "")
        val = int(item.get("value", 0))
        m = re.match(r"^inbound>>>(.+?)>>>traffic>>>(uplink|downlink)$", name)
        if not m:
            continue
        tag, direction = m.group(1), m.group(2)
        if tag == "api":
            continue
        pair = cur_map.setdefault(tag, [0, 0])
        if direction == "uplink":
            pair[0] = val
        else:
            pair[1] = val

    now = time.time()
    today = datetime.date.today().isoformat()
    tot_du = tot_dd = 0

    with TRAFFIC_LOCK:
        deltas = []
        for tag, (cu, cd) in cur_map.items():
            pu, pd = PREV_COUNTERS.get(tag, (None, None))
            if pu is None:
                # First poll after QuackUI start: record baseline without double counting
                PREV_COUNTERS[tag] = (cu, cd)
                continue
            du = cu - pu if cu >= pu else cu
            dd = cd - pd if cd >= pd else cd
            PREV_COUNTERS[tag] = (cu, cd)
            if du > 0 or dd > 0:
                deltas.append((today, tag, du, dd))
                tot_du += du
                tot_dd += dd

        if RATES["ts"] > 0 and now > RATES["ts"]:
            dt = now - RATES["ts"]
            RATES["up"] = tot_du / dt
            RATES["down"] = tot_dd / dt
        RATES["ts"] = now

    if deltas:
        with DB_LOCK, db_conn() as conn:
            for dt_str, tag, du, dd in deltas:
                conn.execute(
                    """
                    INSERT INTO daily_traffic(date, tag, uplink, downlink)
                    VALUES(?,?,?,?)
                    ON CONFLICT(date, tag) DO UPDATE SET
                        uplink = uplink + excluded.uplink,
                        downlink = downlink + excluded.downlink
                    """,
                    (dt_str, tag, du, dd),
                )


def traffic_worker():
    while True:
        try:
            sample_xray_traffic()
        except Exception:
            pass
        time.sleep(5)


def get_traffic_summary():
    today = datetime.date.today().isoformat()
    month_prefix = today[:7] + "%"
    since_14 = (datetime.date.today() - datetime.timedelta(days=13)).isoformat()

    with DB_LOCK, db_conn() as conn:
        t_row = conn.execute(
            "SELECT COALESCE(SUM(uplink),0) u, COALESCE(SUM(downlink),0) d FROM daily_traffic WHERE date=?",
            (today,),
        ).fetchone()
        m_row = conn.execute(
            "SELECT COALESCE(SUM(uplink),0) u, COALESCE(SUM(downlink),0) d FROM daily_traffic WHERE date LIKE ?",
            (month_prefix,),
        ).fetchone()
        a_row = conn.execute(
            "SELECT COALESCE(SUM(uplink),0) u, COALESCE(SUM(downlink),0) d FROM daily_traffic"
        ).fetchone()
        hist_rows = conn.execute(
            "SELECT date, SUM(uplink) u, SUM(downlink) d FROM daily_traffic WHERE date>=? GROUP BY date ORDER BY date ASC",
            (since_14,),
        ).fetchall()
        tag_rows = conn.execute(
            "SELECT tag, SUM(uplink) u, SUM(downlink) d FROM daily_traffic GROUP BY tag"
        ).fetchall()

    hist_map = {r["date"]: {"up": r["u"], "down": r["d"]} for r in hist_rows}
    daily_history = []
    for i in range(13, -1, -1):
        d = (datetime.date.today() - datetime.timedelta(days=i)).isoformat()
        v = hist_map.get(d, {"up": 0, "down": 0})
        daily_history.append({"date": d[5:], "up": v["up"], "down": v["down"]})

    by_tag = {r["tag"]: {"up": r["u"], "down": r["d"]} for r in tag_rows}

    with TRAFFIC_LOCK:
        up_rate = RATES["up"]
        down_rate = RATES["down"]

    return {
        "today": {"up": t_row["u"], "down": t_row["d"]},
        "month": {"up": m_row["u"], "down": m_row["d"]},
        "total": {"up": a_row["u"], "down": a_row["d"]},
        "up_rate": up_rate,
        "down_rate": down_rate,
        "daily_history": daily_history,
        "by_tag": by_tag,
    }


def make_qr_svg(text):
    code, out, _ = run_cmd(["qrencode", "-t", "SVG", "-m", "2", "--inline", "-o", "-", text], timeout=5)
    return out if (code == 0 and "<svg" in out) else ""


def format_node_view(ib, meta, traffic_by_tag):
    tag = ib.get("tag", "unknown")
    listen = str(ib.get("listen", "0.0.0.0"))
    port = ib.get("port", 443)
    proto = ib.get("protocol", "vless")
    clients = ib.get("settings", {}).get("clients", [{}])
    uuid = clients[0].get("id", "") if clients else ""
    flow = clients[0].get("flow", "") if clients else ""
    ss = ib.get("streamSettings", {})
    net = ss.get("network", "raw")
    sec = ss.get("security", "none")
    rs = ss.get("realitySettings", {})
    sni = (rs.get("serverNames") or [""])[0] if sec == "reality" else ""
    sid = (rs.get("shortIds") or [""])[0] if sec == "reality" else ""
    path = ""
    if net == "xhttp":
        path = ss.get("xhttpSettings", {}).get("path", "/")
    elif net == "ws":
        path = ss.get("wsSettings", {}).get("path", "/")

    remark = meta.get("remark") or tag
    pub = meta.get("public_key", "")
    enabled = bool(meta.get("enabled", 1))
    is_v6 = ":" in listen and listen != "::"

    # Build shareable address
    addr = listen
    if listen in ("0.0.0.0", "::", ""):
        addr = detect_public_ipv4()
    host_uri = f"[{addr}]" if ":" in addr and not addr.startswith("[") else addr

    uri = ""
    clash_yaml = ""
    if proto == "vless":
        if sec == "reality":
            uri = (
                f"vless://{uuid}@{host_uri}:{port}"
                f"?encryption=none&flow={quote(flow)}&security=reality"
                f"&sni={quote(sni)}&fp=chrome&pbk={quote(pub)}&sid={quote(sid)}&type=tcp#{quote(remark)}"
            )
            clash_yaml = (
                f"- name: {remark}\n"
                f"  type: vless\n"
                f"  server: {addr}\n"
                f"  port: {port}\n"
                f"  uuid: {uuid}\n"
                f"  network: tcp\n"
                f"  tls: true\n"
                f"  udp: true\n"
                f"  flow: {flow}\n"
                f"  servername: {sni}\n"
                f"  client-fingerprint: chrome\n"
                f"  reality-opts:\n"
                f"    public-key: {pub}\n"
                f"    short-id: {sid}"
            )
        elif net in ("xhttp", "ws"):
            uri = (
                f"vless://{uuid}@{host_uri}:{port}"
                f"?encryption=none&security=tls&sni=YOUR_DOMAIN&fp=chrome&type={net}"
                f"&host=YOUR_DOMAIN&path={quote(path)}#{quote(remark)}"
            )
            clash_yaml = (
                f"- name: {remark}\n"
                f"  type: vless\n"
                f"  server: YOUR_DOMAIN\n"
                f"  port: 443\n"
                f"  uuid: {uuid}\n"
                f"  network: {net}\n"
                f"  tls: true\n"
                f"  servername: YOUR_DOMAIN\n"
                f"  client-fingerprint: chrome\n"
                f"  {net}-opts:\n"
                f"    path: {path}\n"
                f"    headers:\n"
                f"      Host: YOUR_DOMAIN"
            )

    tr = traffic_by_tag.get(tag, {"up": 0, "down": 0})
    return {
        "tag": tag,
        "remark": remark,
        "enabled": enabled,
        "protocol": proto,
        "network": net,
        "security": sec,
        "listen": listen,
        "port": port,
        "is_v6": is_v6,
        "uuid": uuid,
        "flow": flow,
        "sni": sni,
        "pub": pub,
        "sid": sid,
        "path": path,
        "uri": uri,
        "clash_yaml": clash_yaml,
        "traffic": tr,
    }


def list_all_nodes(cfg, traffic_by_tag):
    meta_map = get_meta_map()
    nodes = []
    seen = set()
    for ib in cfg.get("inbounds", []):
        tag = ib.get("tag", "")
        if tag == "api":
            continue
        seen.add(tag)
        meta = meta_map.get(tag, {"remark": tag, "public_key": "", "enabled": 1})
        meta["enabled"] = 1
        nodes.append(format_node_view(ib, meta, traffic_by_tag))

    # Include disabled nodes stored in SQLite
    for tag, meta in meta_map.items():
        if tag not in seen and not meta.get("enabled") and meta.get("disabled_json"):
            try:
                ib = json.loads(meta["disabled_json"])
                nodes.append(format_node_view(ib, meta, traffic_by_tag))
            except Exception:
                pass
    return nodes


def get_routing_state(cfg):
    rules = cfg.get("routing", {}).get("rules", [])
    block_cn = any("geosite:cn" in (r.get("domain") or []) for r in rules)
    block_bt = any("bittorrent" in (r.get("protocol") or []) for r in rules)
    block_private = any("geoip:private" in (r.get("ip") or []) for r in rules)
    strategy = "UseIPv4"
    for ob in cfg.get("outbounds", []):
        if ob.get("tag") == "direct":
            strategy = ob.get("streamSettings", {}).get("sockopt", {}).get("domainStrategy", "AsIs")
            break
    return {
        "block_cn": block_cn,
        "block_bt": block_bt,
        "block_private": block_private,
        "outbound_strategy": strategy,
    }


def apply_routing_state(block_cn, block_bt, block_private, strategy):
    if strategy not in ("UseIPv4", "UseIPv4v6", "UseIPv6v4", "AsIs"):
        raise RuntimeError("不支持的出站策略")
    cfg = read_xray_cfg()
    new_rules = [{"inboundTag": ["api"], "outboundTag": "api"}]
    if block_private:
        new_rules.append({"ip": ["geoip:private"], "outboundTag": "block"})
    if block_bt:
        new_rules.append({"protocol": ["bittorrent"], "outboundTag": "block"})
    if block_cn:
        new_rules.append({"domain": ["geosite:cn"], "outboundTag": "block"})
        new_rules.append({"ip": ["geoip:cn"], "outboundTag": "block"})
    cfg.setdefault("routing", {})["rules"] = new_rules
    cfg.setdefault("dns", {})["queryStrategy"] = "UseIPv4" if strategy == "UseIPv4" else "UseIP"
    for ob in cfg.get("outbounds", []):
        if ob.get("tag") == "direct":
            ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["domainStrategy"] = strategy
    save_xray_cfg(cfg)


def add_node(payload):
    remark = (payload.get("remark") or "").strip()[:40]
    mode = payload.get("mode", "reality")
    listen_type = payload.get("listen_type", "ipv6")
    port = int(payload.get("port", 443))
    if not (1 <= port <= 65535):
        raise RuntimeError("端口范围必须在 1-65535")

    cfg = read_xray_cfg()
    existing_tags = {ib.get("tag") for ib in cfg.get("inbounds", [])} | set(get_meta_map().keys())
    tag = f"node-{secrets.token_hex(3)}"
    while tag in existing_tags:
        tag = f"node-{secrets.token_hex(3)}"

    if listen_type == "ipv6":
        _, _, _, v6_addr = detect_default_v6_iface_and_prefix()
        listen = v6_addr
    elif listen_type == "ipv4":
        listen = "0.0.0.0"
    elif listen_type == "dual":
        listen = "::"
    else:
        listen = "127.0.0.1"

    # Check port conflict on same listen
    for ib in cfg.get("inbounds", []):
        if ib.get("port") == port and ib.get("listen") in (listen, "::", "0.0.0.0"):
            raise RuntimeError(f"端口 {port} 已被节点 {ib.get('tag')} 占用，请换一个端口")

    code, uuid, err = run_cmd(["xray", "uuid"])
    if code != 0 or not uuid:
        raise RuntimeError(f"生成 UUID 失败: {err}")

    pub = ""
    if mode == "reality":
        sni = (payload.get("sni") or "www.berkeley.edu").strip().lower()
        if not re.match(r"^[a-z0-9.-]{3,100}$", sni) or "." not in sni:
            raise RuntimeError("SNI 域名格式不正确")
        priv, pub = generate_x25519()
        sid = secrets.token_hex(8)
        ib = {
            "tag": tag,
            "listen": listen,
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": uuid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "target": f"{sni}:443",
                    "xver": 0,
                    "serverNames": [sni],
                    "privateKey": priv,
                    "shortIds": [sid],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        }
    elif mode in ("xhttp", "ws"):
        path = (payload.get("path") or f"/{secrets.token_hex(6)}").strip()
        if not path.startswith("/"):
            path = "/" + path
        stream = {"network": mode}
        if mode == "xhttp":
            stream["xhttpSettings"] = {"path": path, "mode": "auto", "xPaddingBytes": "100-1000"}
        else:
            stream["wsSettings"] = {"path": path}
        ib = {
            "tag": tag,
            "listen": listen,
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": uuid}], "decryption": "none"},
            "streamSettings": stream,
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        }
    else:
        raise RuntimeError("不支持的节点类型")

    cfg["inbounds"].append(ib)
    save_xray_cfg(cfg)
    set_meta(tag, remark=remark or f"QuackUI-{mode}-{port}", public_key=pub, enabled=1, disabled_json="")
    return tag


def toggle_node(tag):
    cfg = read_xray_cfg()
    meta_map = get_meta_map()
    inbounds = cfg.get("inbounds", [])
    idx = next((i for i, ib in enumerate(inbounds) if ib.get("tag") == tag), None)

    if idx is not None:
        # Disable it
        ib = inbounds.pop(idx)
        save_xray_cfg(cfg)
        set_meta(tag, enabled=0, disabled_json=json.dumps(ib, ensure_ascii=False))
        return False
    else:
        # Enable it
        meta = meta_map.get(tag)
        if not meta or not meta.get("disabled_json"):
            raise RuntimeError("找不到该节点的配置")
        ib = json.loads(meta["disabled_json"])
        inbounds.append(ib)
        save_xray_cfg(cfg)
        set_meta(tag, enabled=1, disabled_json="")
        return True


def delete_node(tag):
    if tag == "api":
        raise RuntimeError("不能删除内部 API 入站")
    cfg = read_xray_cfg()
    cfg["inbounds"] = [ib for ib in cfg.get("inbounds", []) if ib.get("tag") != tag]
    save_xray_cfg(cfg)
    del_meta(tag)


def rotate_ipv6_for_node(tag):
    iface, prefix, plen, base_addr = detect_default_v6_iface_and_prefix()
    g = [secrets.token_hex(2) for _ in range(4)]
    new_v6 = f"{prefix}:{g[0]}:{g[1]}:{g[2]}:{g[3]}"

    code, _, err = run_cmd(["ip", "-6", "addr", "add", f"{new_v6}/{plen}", "dev", iface])
    if code != 0 and "File exists" not in err:
        raise RuntimeError(f"添加 IPv6 地址失败: {err}")

    with open(CUSTOM_V6_IFACE, "w", encoding="utf-8") as f:
        f.write(
            "# Managed by QuackUI\n"
            f"iface {iface} inet6 static\n"
            f"    up ip -6 addr add {new_v6}/{plen} dev {iface} || true\n"
        )

    cfg = read_xray_cfg()
    ib = next((x for x in cfg.get("inbounds", []) if x.get("tag") == tag), None)
    if not ib:
        raise RuntimeError("未找到运行中的目标节点")
    old_v6 = ib["listen"]
    ib["listen"] = new_v6
    save_xray_cfg(cfg)

    if old_v6 != base_addr and old_v6 != new_v6 and ":" in old_v6 and old_v6 != "::":
        # Only delete old_v6 if no other inbound uses it
        if not any(x.get("listen") == old_v6 for x in cfg.get("inbounds", [])):
            run_cmd(["ip", "-6", "addr", "del", f"{old_v6}/{plen}", "dev", iface])

    if tag == "reality-in":
        info = read_node_info()
        info["REALITY_V6"] = new_v6
        write_node_info(info)
    return new_v6


def update_sni_for_node(tag, new_sni):
    new_sni = new_sni.strip().lower()
    if not re.match(r"^[a-z0-9.-]{3,100}$", new_sni) or "." not in new_sni:
        raise RuntimeError("SNI 域名格式不正确")
    code, out, _ = run_cmd(
        ["curl", "-sS", "--max-time", "5", "--tlsv1.3", "--http2", "-o", "/dev/null", "-w", "%{http_code}", f"https://{new_sni}/"],
        timeout=7,
    )
    if code != 0 or out not in ("200", "301", "302", "307", "308"):
        raise RuntimeError(f"目标站点 {new_sni} 未通过 TLS 1.3 + HTTP/2 检测 (HTTP {out or 'ERR'})")

    cfg = read_xray_cfg()
    ib = next((x for x in cfg.get("inbounds", []) if x.get("tag") == tag), None)
    if not ib or ib.get("streamSettings", {}).get("security") != "reality":
        raise RuntimeError("该节点不是运行中的 Reality 节点")
    rs = ib["streamSettings"]["realitySettings"]
    rs["target"] = f"{new_sni}:443"
    rs["serverNames"] = [new_sni]
    save_xray_cfg(cfg)

    if tag == "reality-in":
        info = read_node_info()
        info["REALITY_SNI"] = new_sni
        write_node_info(info)
    return new_sni


def rotate_cred_for_node(tag):
    code, new_uuid, err = run_cmd(["xray", "uuid"])
    if code != 0 or not new_uuid:
        raise RuntimeError(f"生成 UUID 失败: {err}")
    new_sid = secrets.token_hex(8)
    cfg = read_xray_cfg()
    ib = next((x for x in cfg.get("inbounds", []) if x.get("tag") == tag), None)
    if not ib:
        raise RuntimeError("未找到运行中的目标节点")
    ib["settings"]["clients"][0]["id"] = new_uuid
    if ib.get("streamSettings", {}).get("security") == "reality":
        ib["streamSettings"]["realitySettings"]["shortIds"] = [new_sid]
    save_xray_cfg(cfg)

    if tag == "reality-in":
        info = read_node_info()
        info["REALITY_UUID"] = new_uuid
        info["REALITY_SID"] = new_sid
        write_node_info(info)
    return new_uuid, new_sid


def self_check_node(tag="reality-in"):
    cfg = read_xray_cfg()
    meta_map = get_meta_map()
    ib = next((x for x in cfg.get("inbounds", []) if x.get("tag") == tag), None)
    if not ib:
        # fallback to first reality inbound
        ib = next((x for x in cfg.get("inbounds", []) if x.get("streamSettings", {}).get("security") == "reality"), None)
    if not ib:
        raise RuntimeError("没有可自检的 Reality 节点")
    tag = ib["tag"]
    rs = ib["streamSettings"]["realitySettings"]
    pub = meta_map.get(tag, {}).get("public_key") or read_node_info().get("REALITY_PUB", "")
    addr = ib["listen"]
    if addr in ("0.0.0.0", "::", ""):
        addr = "127.0.0.1"
    tmp_cfg = "/tmp/quackui_selfcheck.json"
    client_cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": 10899, "protocol": "socks"}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": addr,
                "port": ib["port"],
                "users": [{"id": ib["settings"]["clients"][0]["id"], "encryption": "none", "flow": "xtls-rprx-vision"}]
            }]},
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "serverName": rs["serverNames"][0],
                    "fingerprint": "chrome",
                    "publicKey": pub,
                    "shortId": rs["shortIds"][0],
                }
            }
        }]
    }
    with open(tmp_cfg, "w", encoding="utf-8") as f:
        json.dump(client_cfg, f)
    p = subprocess.Popen(["xray", "run", "-c", tmp_cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        c1, g_out, _ = run_cmd([
            "curl", "-s", "--max-time", "8", "-x", "socks5h://127.0.0.1:10899",
            "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "https://www.google.com/generate_204"
        ], timeout=10)
        _, ip_out, _ = run_cmd([
            "curl", "-s", "--max-time", "6", "-x", "socks5h://127.0.0.1:10899", "https://ifconfig.co"
        ], timeout=8)
        parts = g_out.split()
        code_str = parts[0] if parts else "000"
        ms = int(float(parts[1]) * 1000) if len(parts) > 1 else 0
        return {
            "ok": c1 == 0 and code_str == "204",
            "tag": tag,
            "http_code": code_str,
            "latency_ms": ms,
            "outbound_ip": ip_out.strip() or "-",
        }
    finally:
        p.terminate()
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
        if os.path.exists(tmp_cfg):
            os.remove(tmp_cfg)


def build_backup_tar_gz():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p, arc in [
            (XRAY_CFG, "xray-config.json"),
            (NFT_CFG, "nftables.conf"),
            (NODE_INFO, "node-info.txt"),
            (DB_PATH, "quackui.db"),
            (CUSTOM_V6_IFACE, "60-custom-v6"),
        ]:
            if os.path.exists(p):
                tar.add(p, arcname=arc)
    return buf.getvalue()


def get_system_stats():
    load1, load5, load15 = os.getloadavg()
    cpus = os.cpu_count() or 1
    mem = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                mem[parts[0].rstrip(":")] = int(parts[1]) * 1024
    mem_total = mem.get("MemTotal", 1)
    mem_used = max(0, mem_total - mem.get("MemAvailable", 0))
    du = shutil.disk_usage("/")
    with open("/proc/uptime", "r", encoding="utf-8") as f:
        up_sec = int(float(f.read().split()[0]))

    svcs = {}
    for s in ("xray", "nftables", "fail2ban"):
        _, o, _ = run_cmd(["systemctl", "is-active", s], timeout=3)
        svcs[s] = o or "unknown"

    f2b_cur = f2b_tot = 0
    _, f2b_out, _ = run_cmd(["fail2ban-client", "status", "sshd"], timeout=3)
    for line in f2b_out.splitlines():
        if "Currently banned:" in line:
            f2b_cur = int(line.split(":")[-1].strip() or 0)
        elif "Total banned:" in line:
            f2b_tot = int(line.split(":")[-1].strip() or 0)

    _, ss_out, _ = run_cmd(["ss", "-Htn", "state", "established", "( sport = :443 )"], timeout=3)
    conns = len([l for l in ss_out.splitlines() if l.strip()])
    _, xray_ver, _ = run_cmd(["xray", "version"], timeout=3)
    xray_ver_short = xray_ver.splitlines()[0].split()[1] if xray_ver else "-"

    return {
        "version": VERSION,
        "xray_version": xray_ver_short,
        "load": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "cpus": cpus,
        "mem_used": mem_used,
        "mem_total": mem_total,
        "disk_used": du.used,
        "disk_total": du.total,
        "uptime_sec": up_sec,
        "services": svcs,
        "fail2ban": {"current": f2b_cur, "total": f2b_tot},
        "active_conns": conns,
    }


def read_web(name):
    with open(os.path.join(WEB_DIR, name), "r", encoding="utf-8") as f:
        return f.read()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _authed(self):
        hdr = self.headers.get("Cookie", "")
        c = cookies.SimpleCookie()
        c.load(hdr)
        m = c.get("quackui_sid")
        if not m:
            return False
        if SESSIONS.get(m.value, 0) > time.time():
            return True
        SESSIONS.pop(m.value, None)
        return False

    def _send_json(self, obj, status=200):
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, body, status=200, extra_headers=None):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _redirect(self, loc, extra_headers=None):
        self.send_response(302)
        self.send_header("Location", loc)
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/login":
            self._send_html(read_web("login.html").replace("__ERR__", ""))
            return
        if path == "/logout":
            self._redirect("/login", [("Set-Cookie", "quackui_sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")])
            return
        if not self._authed():
            if path.startswith("/api/"):
                self._send_json({"ok": False, "err": "unauthorized"}, 401)
            else:
                self._redirect("/login")
            return

        if path == "/":
            self._send_html(read_web("index.html"))
        elif path == "/api/status":
            cfg = read_xray_cfg()
            traffic = get_traffic_summary()
            self._send_json({
                "sys": get_system_stats(),
                "traffic": traffic,
                "nodes": list_all_nodes(cfg, traffic["by_tag"]),
                "routing": get_routing_state(cfg),
            })
        elif path == "/api/logs":
            _, xray_log, _ = run_cmd(["journalctl", "-u", "xray", "-n", "40", "--no-pager"], timeout=5)
            _, f2b_log, _ = run_cmd(["fail2ban-client", "status", "sshd"], timeout=4)
            _, nft_log, _ = run_cmd(["nft", "list", "ruleset"], timeout=4)
            self._send_json({"xray": xray_log, "fail2ban": f2b_log, "firewall": nft_log})
        elif path == "/api/backup":
            data = build_backup_tar_gz()
            fname = f"quackui-backup-{datetime.date.today().strftime('%Y%m%d')}.tar.gz"
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_error(404)

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(min(length, 65536)).decode("utf-8", errors="ignore")

        if path == "/login":
            ip = self.client_address[0]
            fails, until = LOGIN_FAILS.get(ip, [0, 0])
            if until > time.time():
                self._send_html(read_web("login.html").replace("__ERR__", '<div class="err">Too many attempts / 尝试次数过多，请 5 分钟后再试</div>'), 429)
                return
            pw = ""
            for pair in body.split("&"):
                if pair.startswith("password="):
                    pw = unquote_plus(pair.split("=", 1)[1])
            cfg = load_cfg()
            if hmac.compare_digest(hash_password(pw, cfg["salt"]), cfg["password_hash"]):
                LOGIN_FAILS.pop(ip, None)
                tok = secrets.token_hex(24)
                SESSIONS[tok] = time.time() + 86400 * 7
                self._redirect("/", [("Set-Cookie", f"quackui_sid={tok}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax")])
            else:
                fails += 1
                LOGIN_FAILS[ip] = [fails, time.time() + 300 if fails >= 5 else 0]
                self._send_html(read_web("login.html").replace("__ERR__", '<div class="err">Wrong password / 密码错误</div>'), 401)
            return

        if not self._authed():
            self._send_json({"ok": False, "err": "unauthorized"}, 401)
            return

        try:
            data = json.loads(body) if body.strip().startswith("{") else {}
            if path == "/api/qr":
                uri = data.get("uri", "")
                self._send_json({"ok": True, "svg": make_qr_svg(uri)})
            elif path == "/api/nodes/add":
                tag = add_node(data)
                self._send_json({"ok": True, "tag": tag, "msg": f"节点 {tag} 已创建并生效"})
            elif path == "/api/nodes/toggle":
                en = toggle_node(data.get("tag", ""))
                self._send_json({"ok": True, "enabled": en, "msg": "节点已启用" if en else "节点已停用"})
            elif path == "/api/nodes/delete":
                delete_node(data.get("tag", ""))
                self._send_json({"ok": True, "msg": "节点已删除"})
            elif path == "/api/rotate-v6":
                nv6 = rotate_ipv6_for_node(data.get("tag", "reality-in"))
                self._send_json({"ok": True, "msg": f"已切换到新 IPv6: {nv6}"})
            elif path == "/api/set-sni":
                ns = update_sni_for_node(data.get("tag", "reality-in"), data.get("sni", ""))
                self._send_json({"ok": True, "msg": f"已切换伪装域名为 {ns}"})
            elif path == "/api/rotate-cred":
                u, s = rotate_cred_for_node(data.get("tag", "reality-in"))
                self._send_json({"ok": True, "msg": f"已重置密钥 (UUID: {u[:8]}... / SID: {s})"})
            elif path == "/api/routing":
                apply_routing_state(
                    bool(data.get("block_cn", True)),
                    bool(data.get("block_bt", True)),
                    bool(data.get("block_private", True)),
                    data.get("outbound_strategy", "UseIPv4"),
                )
                self._send_json({"ok": True, "msg": "路由与出站策略已保存并生效"})
            elif path == "/api/restart-xray":
                code, _, err = run_cmd(["systemctl", "restart", "xray"])
                if code != 0:
                    raise RuntimeError(err)
                self._send_json({"ok": True, "msg": "Xray 服务已重启"})
            elif path == "/api/self-check":
                res = self_check_node(data.get("tag", "reality-in"))
                self._send_json({"ok": res["ok"], "data": res, "msg": "节点自检通过" if res["ok"] else "节点自检失败"})
            elif path == "/api/change-password":
                old_pw = data.get("old_password", "")
                new_pw = data.get("new_password", "")
                if len(new_pw) < 8:
                    raise RuntimeError("新密码至少需要 8 位字符")
                cfg = load_cfg()
                if not hmac.compare_digest(hash_password(old_pw, cfg["salt"]), cfg["password_hash"]):
                    raise RuntimeError("当前密码不正确")
                new_salt = secrets.token_hex(16)
                cfg["salt"] = new_salt
                cfg["password_hash"] = hash_password(new_pw, new_salt)
                save_cfg(cfg)
                info = read_node_info()
                info["PANEL_PASSWORD"] = new_pw
                write_node_info(info)
                self._send_json({"ok": True, "msg": "面板密码已更新"})
            else:
                self._send_json({"ok": False, "err": "not found"}, 404)
        except Exception as e:
            self._send_json({"ok": False, "err": str(e)}, 400)


if __name__ == "__main__":
    init_db()
    t = threading.Thread(target=traffic_worker, daemon=True)
    t.start()
    cfg = load_cfg()
    host = cfg.get("host", "127.0.0.1")
    port = int(cfg.get("port", 8088))
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"QuackUI v{VERSION} listening on http://{host}:{port}", flush=True)
    srv.serve_forever()
