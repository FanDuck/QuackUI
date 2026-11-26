#!/usr/bin/env python3
"""
QuackUI v2.0.0 - Lightweight, Local-First Xray Management Panel by FanDuck
Zero third-party Python dependencies. Pure Python 3 stdlib + SQLite3.
Listens on 127.0.0.1 by default (accessed via SSH tunnel).
"""

import base64
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
import urllib.request
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote_plus

VERSION = "2.3.5"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
CFG_PATH = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "quackui.db")
SB_CFG = os.path.join(BASE_DIR, "singbox.json")
CERT_DIR = os.path.join(BASE_DIR, "certs")
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
RELEASES_CACHE = {"ts": 0.0, "items": []}


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
                disabled_json TEXT NOT NULL DEFAULT '',
                engine TEXT NOT NULL DEFAULT 'xray',
                hop_range TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS kv_settings (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL DEFAULT ''
            );
        """)
        # Migrate older v2.0/v2.1 DBs missing engine/hop_range columns
        cols = {r[1] for r in conn.execute("PRAGMA table_info(node_meta)").fetchall()}
        if "engine" not in cols:
            conn.execute("ALTER TABLE node_meta ADD COLUMN engine TEXT NOT NULL DEFAULT 'xray'")
        if "hop_range" not in cols:
            conn.execute("ALTER TABLE node_meta ADD COLUMN hop_range TEXT NOT NULL DEFAULT ''")
        if "quota_gb" not in cols:
            conn.execute("ALTER TABLE node_meta ADD COLUMN quota_gb REAL NOT NULL DEFAULT 0")
        if "expire_date" not in cols:
            conn.execute("ALTER TABLE node_meta ADD COLUMN expire_date TEXT NOT NULL DEFAULT ''")
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
    tmp = "/usr/local/etc/xray/.config.tmp.json"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    code, out, err = run_cmd(["xray", "run", "-test", "-c", tmp])
    if code != 0:
        os.remove(tmp)
        detail = (err or out or "unknown error").splitlines()[-1]
        raise RuntimeError(f"Xray 配置校验失败: {detail}")
    shutil.move(tmp, XRAY_CFG)
    run_cmd(["systemctl", "reset-failed", "xray"], timeout=5)
    code, out, err = run_cmd(["systemctl", "restart", "xray"])
    if code != 0:
        raise RuntimeError(f"重启 Xray 失败: {err or out}")


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


def set_meta(tag, remark=None, public_key=None, enabled=None, disabled_json=None, engine=None, hop_range=None, quota_gb=None, expire_date=None):
    with DB_LOCK, db_conn() as conn:
        cur = conn.execute("SELECT * FROM node_meta WHERE tag=?", (tag,)).fetchone()
        if not cur:
            conn.execute(
                "INSERT INTO node_meta(tag, remark, public_key, enabled, disabled_json, engine, hop_range, quota_gb, expire_date) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    tag,
                    remark if remark is not None else tag,
                    public_key if public_key is not None else "",
                    1 if enabled is None else int(enabled),
                    disabled_json if disabled_json is not None else "",
                    engine if engine is not None else "xray",
                    hop_range if hop_range is not None else "",
                    float(quota_gb) if quota_gb is not None else 0.0,
                    expire_date if expire_date is not None else "",
                ),
            )
        else:
            conn.execute(
                "UPDATE node_meta SET remark=?, public_key=?, enabled=?, disabled_json=?, engine=?, hop_range=?, quota_gb=?, expire_date=? WHERE tag=?",
                (
                    remark if remark is not None else cur["remark"],
                    public_key if public_key is not None else cur["public_key"],
                    int(enabled) if enabled is not None else cur["enabled"],
                    disabled_json if disabled_json is not None else cur["disabled_json"],
                    engine if engine is not None else cur["engine"],
                    hop_range if hop_range is not None else cur["hop_range"],
                    float(quota_gb) if quota_gb is not None else float(cur["quota_gb"] or 0),
                    expire_date if expire_date is not None else (cur["expire_date"] or ""),
                    tag,
                ),
            )


def get_singbox_version():
    if not shutil.which("sing-box") and not os.path.exists("/usr/local/bin/sing-box"):
        return ""
    _, out, _ = run_cmd(["/usr/local/bin/sing-box", "version"], timeout=3)
    if out:
        parts = out.splitlines()[0].split()
        if len(parts) >= 3:
            return parts[2]
    return ""


def ensure_singbox_service():
    unit = "/etc/systemd/system/quackui-singbox.service"
    if not os.path.exists(unit):
        with open(unit, "w", encoding="utf-8") as f:
            f.write(
                "[Unit]\n"
                "Description=QuackUI sing-box Engine\n"
                "After=network-online.target\n\n"
                "[Service]\n"
                "Type=simple\n"
                f"ExecStart=/usr/local/bin/sing-box run -c {SB_CFG}\n"
                "Restart=always\n"
                "RestartSec=3\n\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
            )
        run_cmd(["systemctl", "daemon-reload"], timeout=10)


def install_or_upgrade_singbox():
    import platform
    m = platform.machine()
    arch = "amd64" if m == "x86_64" else ("arm64" if m in ("aarch64", "arm64") else "")
    if not arch:
        raise RuntimeError(f"不支持的架构: {m}")
    req = urllib.request.Request(
        "https://api.github.com/repos/SagerNet/sing-box/releases/latest",
        headers={"User-Agent": f"QuackUI/{VERSION}"},
    )
    with urllib.request.urlopen(req, timeout=12) as r:
        ver = json.loads(r.read().decode("utf-8"))["tag_name"].lstrip("v")
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{ver}/sing-box-{ver}-linux-{arch}.tar.gz"
    cmd = (
        f'curl -fsSL "{url}" -o /tmp/sb_up.tar.gz && tar -xzf /tmp/sb_up.tar.gz -C /tmp && '
        f'install -m 755 "/tmp/sing-box-{ver}-linux-{arch}/sing-box" /usr/local/bin/sing-box && '
        f'rm -rf /tmp/sb_up.tar.gz "/tmp/sing-box-{ver}-linux-{arch}"'
    )
    code, _, err = run_cmd(["bash", "-c", cmd], timeout=120)
    if code != 0:
        raise RuntimeError(f"安装 sing-box 失败: {err[-180:]}")
    ensure_singbox_service()
    if os.path.exists(SB_CFG) and read_singbox_cfg().get("inbounds"):
        run_cmd(["systemctl", "restart", "quackui-singbox"], timeout=10)
    return get_singbox_version()


def read_singbox_cfg():
    if os.path.exists(SB_CFG):
        try:
            with open(SB_CFG, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "log": {"level": "warn"},
        "dns": {"servers": [{"tag": "local", "type": "local"}], "strategy": "ipv4_only"},
        "inbounds": [],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default_domain_resolver": {"server": "local", "strategy": "ipv4_only"}},
    }


def save_singbox_cfg(cfg):
    ensure_singbox_service()
    if not cfg.get("inbounds"):
        with open(SB_CFG, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        run_cmd(["systemctl", "disable", "--now", "quackui-singbox"], timeout=10)
        return
    if not os.path.exists("/usr/local/bin/sing-box"):
        raise RuntimeError("请先在「内核与设置」中一键安装 sing-box 内核")
    tmp = SB_CFG + ".tmp.json"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    code, out, err = run_cmd(["/usr/local/bin/sing-box", "check", "-c", tmp], timeout=10)
    if code != 0:
        os.remove(tmp)
        raise RuntimeError(f"sing-box 配置校验失败: {(err or out)[-200:]}")
    shutil.move(tmp, SB_CFG)
    run_cmd(["systemctl", "reset-failed", "quackui-singbox"], timeout=5)
    code, out, err = run_cmd(["systemctl", "enable", "--now", "quackui-singbox"], timeout=10)
    code2, out2, err2 = run_cmd(["systemctl", "restart", "quackui-singbox"], timeout=10)
    if code2 != 0:
        raise RuntimeError(f"重启 sing-box 失败: {err2 or out2}")


def ensure_self_signed_cert(tag, sni):
    os.makedirs(CERT_DIR, exist_ok=True)
    crt = os.path.join(CERT_DIR, f"{tag}.crt")
    key = os.path.join(CERT_DIR, f"{tag}.key")
    code, _, err = run_cmd([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-days", "3650", "-subj", f"/CN={sni}",
        "-addext", f"subjectAltName=DNS:{sni}", "-keyout", key, "-out", crt
    ], timeout=10)
    if code != 0:
        raise RuntimeError(f"生成自签证书失败: {err}")
    os.chmod(key, 0o600)
    return crt, key


def sync_nftables():
    """Auto-sync nftables firewall rules to match all active Xray + sing-box nodes (always keeps SSH 22)."""
    if not shutil.which("nft") or not os.path.exists(NFT_CFG):
        return
    xray_cfg = read_xray_cfg()
    sb_cfg = read_singbox_cfg()
    meta_map = get_meta_map()

    tcp_v4, tcp_v6, tcp_any = set(), set(), set()
    udp_v4, udp_v6, udp_any = set(), set(), set()
    hy2_hops = []  # (family, hop_range, listen_port)

    def add_port(listen, port, proto_kind, hop_range=""):
        if listen in ("127.0.0.1", "::1") or str(listen).startswith("/"):
            return
        is_v6_only = ":" in str(listen) and str(listen) != "::"
        is_v4_only = "." in str(listen) and str(listen) != "0.0.0.0"
        if proto_kind in ("tcp", "both"):
            if is_v6_only:
                tcp_v6.add(port)
            elif is_v4_only:
                tcp_v4.add(port)
            else:
                tcp_any.add(port)
        if proto_kind in ("udp", "both"):
            if is_v6_only:
                udp_v6.add(port)
            elif is_v4_only:
                udp_v4.add(port)
            else:
                udp_any.add(port)
        if hop_range and re.match(r"^\d+-\d+$", hop_range):
            fam = "ipv6" if is_v6_only else ("ipv4" if is_v4_only else "any")
            hy2_hops.append((fam, hop_range, port))

    for ib in xray_cfg.get("inbounds", []):
        if ib.get("tag") == "api":
            continue
        pkind = "both" if ib.get("protocol") == "shadowsocks" else "tcp"
        add_port(ib.get("listen", "0.0.0.0"), int(ib.get("port", 443)), pkind)

    for ib in sb_cfg.get("inbounds", []):
        tag = ib.get("tag", "")
        t = ib.get("type", "")
        pkind = "udp" if t in ("hysteria2", "tuic") else "tcp"
        hop = meta_map.get(tag, {}).get("hop_range", "") if t == "hysteria2" else ""
        add_port(ib.get("listen", "::"), int(ib.get("listen_port", 443)), pkind, hop)

    lines = [
        "#!/usr/sbin/nft -f",
        "flush ruleset",
        "table inet filter {",
        "    chain input {",
        "        type filter hook input priority 0; policy drop;",
        "        ct state established,related accept",
        "        ct state invalid drop",
        "        iif lo accept",
        "        ip protocol icmp accept",
        "        ip6 nexthdr icmpv6 accept",
        "        tcp dport 22 accept",
    ]
    if tcp_any:
        lines.append(f"        tcp dport {{ {', '.join(str(p) for p in sorted(tcp_any))} }} accept")
    if tcp_v4:
        lines.append(f"        meta nfproto ipv4 tcp dport {{ {', '.join(str(p) for p in sorted(tcp_v4))} }} accept")
    if tcp_v6:
        lines.append(f"        meta nfproto ipv6 tcp dport {{ {', '.join(str(p) for p in sorted(tcp_v6))} }} accept")
    if udp_any:
        lines.append(f"        udp dport {{ {', '.join(str(p) for p in sorted(udp_any))} }} accept")
    if udp_v4:
        lines.append(f"        meta nfproto ipv4 udp dport {{ {', '.join(str(p) for p in sorted(udp_v4))} }} accept")
    if udp_v6:
        lines.append(f"        meta nfproto ipv6 udp dport {{ {', '.join(str(p) for p in sorted(udp_v6))} }} accept")
    for fam, hr, _ in hy2_hops:
        pref = "" if fam == "any" else f"meta nfproto {fam} "
        lines.append(f"        {pref}udp dport {hr} accept")

    lines += [
        "    }",
        "    chain forward { type filter hook forward priority 0; policy drop; }",
        "    chain output  { type filter hook output priority 0; policy accept; }",
        "}",
    ]

    if hy2_hops:
        lines += [
            "table inet hy2_hop {",
            "    chain prerouting {",
            "        type nat hook prerouting priority dstnat; policy accept;",
        ]
        for fam, hr, lp in hy2_hops:
            pref = "" if fam == "any" else f"meta nfproto {fam} "
            lines.append(f"        {pref}udp dport {hr} redirect to :{lp}")
        lines += ["    }", "}"]

    tmp = "/etc/nftables.conf.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    code, _, _ = run_cmd(["nft", "-c", "-f", tmp], timeout=5)
    if code == 0:
        shutil.move(tmp, NFT_CFG)
        run_cmd(["nft", "-f", NFT_CFG], timeout=5)
    else:
        os.remove(tmp)


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


def enforce_node_limits():
    """Auto-disable active nodes that exceed their traffic quota or expiration date."""
    today = datetime.date.today().isoformat()
    meta_map = get_meta_map()
    if not meta_map:
        return
    tr = get_traffic_summary()["by_tag"]
    for tag, meta in meta_map.items():
        if not meta.get("enabled"):
            continue
        quota_gb = float(meta.get("quota_gb") or 0)
        exp = (meta.get("expire_date") or "").strip()
        exceeded = False
        if quota_gb > 0:
            used = tr.get(tag, {"up": 0, "down": 0})
            if (used["up"] + used["down"]) >= quota_gb * (1024 ** 3):
                exceeded = True
        if exp and today > exp:
            exceeded = True
        if exceeded:
            try:
                toggle_node(tag)
            except Exception:
                pass


def traffic_worker():
    tick = 0
    while True:
        try:
            sample_xray_traffic()
            tick += 1
            if tick % 12 == 0:  # Every ~60s check quota & expiration limits
                enforce_node_limits()
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
    settings = ib.get("settings", {})
    clients = settings.get("clients", [{}])
    uuid = clients[0].get("id", "") if clients else ""
    password = clients[0].get("password", "") if clients else ""
    flow = clients[0].get("flow", "") if clients else ""
    ss_method = settings.get("method", "")
    ss_pass = settings.get("password", "")

    ss = ib.get("streamSettings", {})
    net = ss.get("network", "raw")
    sec = ss.get("security", "none")
    rs = ss.get("realitySettings", {})
    tls_s = ss.get("tlsSettings", {})
    sni = ""
    sid = ""
    if sec == "reality":
        sni = (rs.get("serverNames") or [""])[0]
        sid = (rs.get("shortIds") or [""])[0]
    elif sec == "tls":
        sni = tls_s.get("serverName", "")

    path = ""
    if net == "xhttp":
        path = ss.get("xhttpSettings", {}).get("path", "/")
    elif net == "ws":
        path = ss.get("wsSettings", {}).get("path", "/")
    elif net == "grpc":
        path = ss.get("grpcSettings", {}).get("serviceName", "")

    remark = meta.get("remark") or tag
    pub = meta.get("public_key", "")
    enabled = bool(meta.get("enabled", 1))
    is_v6 = ":" in listen and listen != "::"

    addr = listen
    if listen in ("0.0.0.0", "::", "", "127.0.0.1"):
        addr = detect_public_ipv4()
    host_uri = f"[{addr}]" if ":" in addr and not addr.startswith("[") else addr
    net_clash = "tcp" if net == "raw" else net

    uri = ""
    clash_yaml = ""

    if proto == "vless":
        params = ["encryption=none"]
        if flow and net == "raw" and sec == "reality":
            params.append(f"flow={quote(flow)}")
        params.append(f"security={sec}")
        if sec == "reality":
            params += [f"sni={quote(sni)}", "fp=chrome", f"pbk={quote(pub)}", f"sid={quote(sid)}"]
        elif sec == "tls":
            params += [f"sni={quote(sni or 'YOUR_DOMAIN')}", "fp=chrome"]
        params.append(f"type={'tcp' if net == 'raw' else net}")
        if net in ("ws", "xhttp"):
            params.append(f"path={quote(path or '/')}")
            if net == "xhttp":
                params.append("mode=auto")
            if sni:
                params.append(f"host={quote(sni)}")
        elif net == "grpc":
            params.append(f"serviceName={quote(path)}")
        uri = f"vless://{uuid}@{host_uri}:{port}?{'&'.join(params)}#{quote(remark)}"

        lines = [
            f"- name: {remark}",
            "  type: vless",
            f"  server: {addr}",
            f"  port: {port}",
            f"  uuid: {uuid}",
            f"  network: {net_clash}",
            "  udp: true",
        ]
        if sec in ("reality", "tls"):
            lines += ["  tls: true", f"  servername: {sni or 'YOUR_DOMAIN'}", "  client-fingerprint: chrome"]
            if flow and net == "raw":
                lines.append(f"  flow: {flow}")
        if sec == "reality":
            lines += ["  reality-opts:", f"    public-key: {pub}", f"    short-id: {sid}"]
        if net in ("ws", "xhttp"):
            lines += [f"  {net}-opts:", f"    path: {path or '/'}"]
        elif net == "grpc":
            lines += ["  grpc-opts:", f"    grpc-service-name: {path}"]
        clash_yaml = "\n".join(lines)

    elif proto == "vmess":
        vm_obj = {
            "v": "2",
            "ps": remark,
            "add": addr,
            "port": str(port),
            "id": uuid,
            "aid": "0",
            "scy": "auto",
            "net": "tcp" if net == "raw" else net,
            "type": "none",
            "host": sni,
            "path": path,
            "tls": "tls" if sec == "tls" else "",
            "sni": sni if sec == "tls" else "",
        }
        b64 = base64.b64encode(json.dumps(vm_obj, separators=(",", ":")).encode("utf-8")).decode("ascii")
        uri = f"vmess://{b64}"
        lines = [
            f"- name: {remark}",
            "  type: vmess",
            f"  server: {addr}",
            f"  port: {port}",
            f"  uuid: {uuid}",
            "  alterId: 0",
            "  cipher: auto",
            f"  network: {net_clash}",
            "  udp: true",
        ]
        if sec == "tls":
            lines += ["  tls: true", f"  servername: {sni or 'YOUR_DOMAIN'}"]
        if net == "ws":
            lines += ["  ws-opts:", f"    path: {path or '/'}"]
        elif net == "grpc":
            lines += ["  grpc-opts:", f"    grpc-service-name: {path}"]
        clash_yaml = "\n".join(lines)

    elif proto == "trojan":
        params = [f"security={sec}", f"type={'tcp' if net == 'raw' else net}"]
        if sec == "reality":
            params += [f"sni={quote(sni)}", "fp=chrome", f"pbk={quote(pub)}", f"sid={quote(sid)}"]
        elif sec == "tls":
            params += [f"sni={quote(sni or 'YOUR_DOMAIN')}", "fp=chrome"]
        if net == "ws":
            params.append(f"path={quote(path or '/')}")
        elif net == "grpc":
            params.append(f"serviceName={quote(path)}")
        uri = f"trojan://{quote(password)}@{host_uri}:{port}?{'&'.join(params)}#{quote(remark)}"
        lines = [
            f"- name: {remark}",
            "  type: trojan",
            f"  server: {addr}",
            f"  port: {port}",
            f"  password: {password}",
            f"  network: {net_clash}",
            "  udp: true",
        ]
        if sec in ("reality", "tls"):
            lines += [f"  sni: {sni or 'YOUR_DOMAIN'}", "  client-fingerprint: chrome"]
        if sec == "reality":
            lines += ["  reality-opts:", f"    public-key: {pub}", f"    short-id: {sid}"]
        if net == "ws":
            lines += ["  ws-opts:", f"    path: {path or '/'}"]
        elif net == "grpc":
            lines += ["  grpc-opts:", f"    grpc-service-name: {path}"]
        clash_yaml = "\n".join(lines)

    elif proto == "shadowsocks":
        userinfo = base64.urlsafe_b64encode(f"{ss_method}:{ss_pass}".encode("utf-8")).decode("ascii").rstrip("=")
        uri = f"ss://{userinfo}@{host_uri}:{port}#{quote(remark)}"
        clash_yaml = "\n".join([
            f"- name: {remark}",
            "  type: ss",
            f"  server: {addr}",
            f"  port: {port}",
            f"  cipher: {ss_method}",
            f"  password: {ss_pass}",
            "  udp: true",
        ])

    tr = traffic_by_tag.get(tag, {"up": 0, "down": 0})
    client_list = []
    if proto in ("vless", "vmess"):
        for idx, c in enumerate(clients):
            cname = c.get("email") or f"user-{idx+1}"
            cid = c.get("id", "")
            c_uri = uri.replace(uuid, cid, 1) if (uri and uuid and cid) else uri
            client_list.append({"name": cname, "id": cid, "uri": c_uri})
    elif proto == "trojan":
        for idx, c in enumerate(clients):
            cname = c.get("email") or f"user-{idx+1}"
            cpw = c.get("password", "")
            c_uri = uri.replace(quote(password), quote(cpw), 1) if (uri and password and cpw) else uri
            client_list.append({"name": cname, "id": cpw, "uri": c_uri})
    else:
        client_list.append({"name": "default", "id": ss_pass, "uri": uri})

    return {
        "tag": tag,
        "engine": "xray",
        "remark": remark,
        "enabled": enabled,
        "protocol": proto,
        "network": net,
        "security": sec,
        "listen": listen,
        "port": port,
        "is_v6": is_v6,
        "uuid": uuid or password or ss_pass,
        "ss_method": ss_method,
        "flow": flow,
        "sni": sni,
        "pub": pub,
        "sid": sid,
        "path": path,
        "hop_range": "",
        "quota_gb": float(meta.get("quota_gb") or 0),
        "expire_date": meta.get("expire_date") or "",
        "clients": client_list,
        "uri": uri,
        "clash_yaml": clash_yaml,
        "traffic": tr,
    }


def format_singbox_node_view(ib, meta, traffic_by_tag):
    tag = ib.get("tag", "sb-node")
    proto = ib.get("type", "anytls")
    listen = str(ib.get("listen", "::"))
    port = int(ib.get("listen_port", 443))
    users = ib.get("users") or [{}]
    u0 = users[0] if users else {}
    uuid = u0.get("uuid", "")
    pw = u0.get("password", "")
    sni = ib.get("tls", {}).get("server_name", "www.bing.com")
    remark = meta.get("remark") or tag
    enabled = bool(meta.get("enabled", 1))
    hop_range = meta.get("hop_range", "")
    is_v6 = ":" in listen and listen != "::"

    addr = detect_public_ipv4() if listen in ("0.0.0.0", "::", "", "127.0.0.1") else listen
    host_uri = f"[{addr}]" if ":" in addr and not addr.startswith("[") else addr

    uri = ""
    clash_yaml = ""
    net = "udp" if proto in ("hysteria2", "tuic") else "tcp"
    if proto == "anytls":
        uri = f"anytls://{quote(pw)}@{host_uri}:{port}?sni={quote(sni)}&insecure=1#{quote(remark)}"
        clash_yaml = "\n".join([
            f"- name: {remark}",
            "  type: anytls",
            f"  server: {addr}",
            f"  port: {port}",
            f"  password: {pw}",
            f"  sni: {sni}",
            "  skip-cert-verify: true",
            "  udp: true",
        ])
    elif proto == "hysteria2":
        mport_q = f"&mport={quote(hop_range)}" if hop_range else ""
        uri = f"hysteria2://{quote(pw)}@{host_uri}:{port}?sni={quote(sni)}{mport_q}&insecure=1#{quote(remark)}"
        lines = [
            f"- name: {remark}",
            "  type: hysteria2",
            f"  server: {addr}",
            f"  port: {port}",
            f"  password: {pw}",
            f"  sni: {sni}",
            "  skip-cert-verify: true",
        ]
        if hop_range:
            lines.append(f"  ports: {hop_range}")
        clash_yaml = "\n".join(lines)
    elif proto == "tuic":
        uri = f"tuic://{uuid}:{quote(pw)}@{host_uri}:{port}?sni={quote(sni)}&congestion_control=bbr&alpn=h3&allow_insecure=1#{quote(remark)}"
        clash_yaml = "\n".join([
            f"- name: {remark}",
            "  type: tuic",
            f"  server: {addr}",
            f"  port: {port}",
            f"  uuid: {uuid}",
            f"  password: {pw}",
            f"  sni: {sni}",
            "  alpn: [h3]",
            "  congestion-controller: bbr",
            "  skip-cert-verify: true",
            "  udp-relay-mode: native",
        ])

    client_list = []
    for idx, u in enumerate(users):
        uname = u.get("name") or f"user-{idx+1}"
        upw = u.get("password", "")
        uu = u.get("uuid", "")
        c_uri = uri
        if proto == "anytls":
            c_uri = f"anytls://{quote(upw)}@{host_uri}:{port}?sni={quote(sni)}&insecure=1#{quote(remark + '-' + uname)}"
        elif proto == "hysteria2":
            mport_q = f"&mport={quote(hop_range)}" if hop_range else ""
            c_uri = f"hysteria2://{quote(upw)}@{host_uri}:{port}?sni={quote(sni)}{mport_q}&insecure=1#{quote(remark + '-' + uname)}"
        elif proto == "tuic":
            c_uri = f"tuic://{uu}:{quote(upw)}@{host_uri}:{port}?sni={quote(sni)}&congestion_control=bbr&alpn=h3&allow_insecure=1#{quote(remark + '-' + uname)}"
        client_list.append({"name": uname, "id": f"{uu} / {upw}" if (uu and upw) else upw, "uri": c_uri})

    return {
        "tag": tag,
        "engine": "sing-box",
        "remark": remark,
        "enabled": enabled,
        "protocol": proto,
        "network": net,
        "security": "tls",
        "listen": listen,
        "port": port,
        "is_v6": is_v6,
        "uuid": f"{uuid} / {pw}" if (uuid and pw) else (pw or uuid),
        "ss_method": "",
        "flow": "",
        "sni": sni,
        "pub": "",
        "sid": "",
        "path": "",
        "hop_range": hop_range,
        "quota_gb": float(meta.get("quota_gb") or 0),
        "expire_date": meta.get("expire_date") or "",
        "clients": client_list,
        "uri": uri,
        "clash_yaml": clash_yaml,
        "traffic": traffic_by_tag.get(tag, {"up": 0, "down": 0}),
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
        meta = dict(meta_map.get(tag, {"remark": tag, "public_key": "", "enabled": 1, "engine": "xray"}))
        meta["enabled"] = 1
        nodes.append(format_node_view(ib, meta, traffic_by_tag))

    sb_cfg = read_singbox_cfg()
    for ib in sb_cfg.get("inbounds", []):
        tag = ib.get("tag", "")
        seen.add(tag)
        meta = dict(meta_map.get(tag, {"remark": tag, "enabled": 1, "engine": "sing-box", "hop_range": ""}))
        meta["enabled"] = 1
        nodes.append(format_singbox_node_view(ib, meta, traffic_by_tag))

    for tag, meta in meta_map.items():
        if tag not in seen and not meta.get("enabled") and meta.get("disabled_json"):
            try:
                ib = json.loads(meta["disabled_json"])
                if meta.get("engine") == "sing-box":
                    nodes.append(format_singbox_node_view(ib, meta, traffic_by_tag))
                else:
                    nodes.append(format_node_view(ib, meta, traffic_by_tag))
            except Exception:
                pass
    return nodes


AI_STREAM_DOMAINS = [
    "domain:openai.com",
    "domain:chatgpt.com",
    "domain:oaistatic.com",
    "domain:oaiusercontent.com",
    "domain:anthropic.com",
    "domain:claude.ai",
    "domain:gemini.google.com",
    "domain:aistudio.google.com",
    "domain:generativelanguage.googleapis.com",
    "domain:perplexity.ai",
    "domain:netflix.com",
    "domain:nflxvideo.net",
    "domain:disneyplus.com",
    "domain:tiktok.com",
    "domain:tiktokv.com",
    "domain:byteoversea.com",
]


def get_socks5_cfg():
    default = {
        "enabled": False,
        "mode": "all",
        "host": "",
        "port": 1080,
        "username": "",
        "password": "",
        "custom_domains": "",
    }
    with DB_LOCK, db_conn() as conn:
        row = conn.execute("SELECT v FROM kv_settings WHERE k='socks5_outbound'").fetchone()
    if row and row["v"]:
        try:
            default.update(json.loads(row["v"]))
        except Exception:
            pass
    return default


def set_socks5_cfg(s5):
    with DB_LOCK, db_conn() as conn:
        conn.execute(
            "INSERT INTO kv_settings(k, v) VALUES('socks5_outbound', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (json.dumps(s5, ensure_ascii=False),),
        )


def test_socks5_connectivity(host, port, username="", password=""):
    host = (host or "").strip()
    port = int(port or 0)
    if not host or not (1 <= port <= 65535):
        raise RuntimeError("请填写正确的 SOCKS5 地址和端口")
    proxy_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    proxy_url = f"socks5h://{proxy_host}:{port}"
    cmd = ["curl", "-sS", "--max-time", "10", "-x", proxy_url]
    if username or password:
        cmd += ["--proxy-user", f"{username}:{password}"]
    cmd += ["-w", "\n%{time_total}", "https://ipinfo.io/json"]
    code, out, err = run_cmd(cmd, timeout=12)
    if code != 0 or not out:
        raise RuntimeError(f"SOCKS5 连接失败: {(err or '超时或认证错误')[-160:]}")
    lines = out.splitlines()
    latency_ms = 0
    if len(lines) >= 2:
        try:
            latency_ms = int(float(lines[-1]) * 1000)
            json_body = "\n".join(lines[:-1])
        except Exception:
            json_body = out
    else:
        json_body = out
    info = json.loads(json_body)
    return {
        "ip": info.get("ip", "-"),
        "country": info.get("country", "-"),
        "region": info.get("region", ""),
        "city": info.get("city", ""),
        "org": info.get("org", "-"),
        "latency_ms": latency_ms,
    }


def _apply_socks5_to_xray_cfg(cfg, s5):
    """Sync socks5-out outbound and its routing rules into Xray config dict."""
    outbounds = [ob for ob in cfg.get("outbounds", []) if ob.get("tag") != "socks5-out"]
    rules = [r for r in cfg.get("routing", {}).get("rules", []) if r.get("outboundTag") != "socks5-out"]

    if s5.get("enabled") and s5.get("host"):
        server_obj = {"address": s5["host"], "port": int(s5["port"])}
        if s5.get("username") or s5.get("password"):
            server_obj["users"] = [{"user": s5.get("username", ""), "pass": s5.get("password", "")}]
        outbounds.append({
            "protocol": "socks",
            "tag": "socks5-out",
            "settings": {"servers": [server_obj]},
        })

        mode = s5.get("mode", "all")
        custom_list = []
        for raw_d in re.split(r"[\s,;]+", s5.get("custom_domains") or ""):
            d = raw_d.strip().lower()
            if d and "." in d:
                custom_list.append(d if ":" in d else f"domain:{d}")

        if mode == "all":
            rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "socks5-out"})
        elif mode == "ai_stream":
            domains = list(dict.fromkeys(AI_STREAM_DOMAINS + custom_list))
            rules.append({"type": "field", "domain": domains, "outboundTag": "socks5-out"})
        elif mode == "custom":
            if not custom_list:
                raise RuntimeError("自定义分流模式请至少填写一个域名")
            rules.append({"type": "field", "domain": custom_list, "outboundTag": "socks5-out"})

    cfg["outbounds"] = outbounds
    cfg.setdefault("routing", {})["rules"] = rules


def _apply_socks5_to_singbox_cfg(sb_cfg, s5):
    """Sync residential SOCKS5 outbound and routing rules into sing-box config."""
    outbounds = [ob for ob in sb_cfg.get("outbounds", []) if ob.get("tag") != "socks5-out"]
    route = sb_cfg.setdefault("route", {})
    rules = [r for r in route.get("rules", []) if r.get("outbound") != "socks5-out"]

    if s5.get("enabled") and s5.get("host"):
        ob = {"type": "socks", "tag": "socks5-out", "server": s5["host"], "server_port": int(s5["port"])}
        if s5.get("username") or s5.get("password"):
            ob["username"] = s5.get("username", "")
            ob["password"] = s5.get("password", "")
        outbounds.append(ob)

        mode = s5.get("mode", "all")
        custom_domains = []
        for raw_d in re.split(r"[\s,;]+", s5.get("custom_domains") or ""):
            d = raw_d.strip().lower().removeprefix("domain:")
            if d and "." in d:
                custom_domains.append(d)

        if mode == "all":
            route["final"] = "socks5-out"
        else:
            route["final"] = "direct"
            if mode == "ai_stream":
                base = [x.removeprefix("domain:") for x in AI_STREAM_DOMAINS]
                domains = list(dict.fromkeys(base + custom_domains))
            else:
                domains = custom_domains
            if domains:
                rules.append({"domain_suffix": domains, "outbound": "socks5-out"})
    else:
        route["final"] = "direct"

    sb_cfg["outbounds"] = outbounds
    route["rules"] = rules


def save_socks5_routing(payload):
    enabled = bool(payload.get("enabled", False))
    mode = payload.get("mode", "all")
    if mode not in ("all", "ai_stream", "custom"):
        raise RuntimeError("不支持的路由模式")
    host = (payload.get("host") or "").strip()
    port = int(payload.get("port") or 1080)
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    custom_domains = (payload.get("custom_domains") or "").strip()

    if enabled:
        if not host or not (1 <= port <= 65535):
            raise RuntimeError("启用家宽路由需要填写有效的 SOCKS5 地址和端口")

    s5 = {
        "enabled": enabled,
        "mode": mode,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "custom_domains": custom_domains,
    }
    cfg = read_xray_cfg()
    _apply_socks5_to_xray_cfg(cfg, s5)
    save_xray_cfg(cfg)

    # Also sync to sing-box config so AnyTLS/Hy2/TUIC share the same residential exit
    if os.path.exists(SB_CFG) or read_singbox_cfg().get("inbounds"):
        sb_cfg = read_singbox_cfg()
        _apply_socks5_to_singbox_cfg(sb_cfg, s5)
        save_singbox_cfg(sb_cfg)

    set_socks5_cfg(s5)
    return s5


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
    _apply_socks5_to_xray_cfg(cfg, get_socks5_cfg())
    save_xray_cfg(cfg)


def add_node(payload):
    remark = (payload.get("remark") or "").strip()[:40]
    protocol = (payload.get("protocol") or payload.get("mode") or "vless").strip().lower()
    transport = (payload.get("transport") or "raw").strip().lower()
    security = (payload.get("security") or "reality").strip().lower()
    listen_type = (payload.get("listen_type") or "ipv6").strip().lower()
    port = int(payload.get("port") or 8443)
    if not (1 <= port <= 65535):
        raise RuntimeError("端口范围必须在 1-65535")

    # Backward compatibility with v2.0.x mode names
    if protocol == "reality":
        protocol, transport, security = "vless", "raw", "reality"
    elif protocol in ("xhttp", "ws"):
        protocol, transport, security = "vless", protocol, "none"

    if protocol in ("anytls", "hysteria2", "tuic"):
        if not os.path.exists("/usr/local/bin/sing-box"):
            raise RuntimeError("请先在「内核与设置」中点击一键安装 sing-box 内核")
        sb_cfg = read_singbox_cfg()
        existing_tags = {ib.get("tag") for ib in sb_cfg.get("inbounds", [])} | set(get_meta_map().keys())
        tag = f"sb-{protocol[:3]}-{secrets.token_hex(2)}"
        while tag in existing_tags:
            tag = f"sb-{protocol[:3]}-{secrets.token_hex(2)}"

        if listen_type == "ipv6":
            _, _, _, v6_addr = detect_default_v6_iface_and_prefix()
            listen = v6_addr
        elif listen_type == "ipv4":
            listen = "0.0.0.0"
        elif listen_type == "dual":
            listen = "::"
        else:
            listen = "127.0.0.1"

        sni = (payload.get("sni") or "www.bing.com").strip().lower()
        if not re.match(r"^[a-z0-9.-]{3,100}$", sni) or "." not in sni:
            raise RuntimeError("SNI 域名格式不正确")
        crt, key = ensure_self_signed_cert(tag, sni)
        pw = secrets.token_urlsafe(16)
        hop_range = (payload.get("hop_range") or "").strip()
        if hop_range and not re.match(r"^\d+-\d+$", hop_range):
            raise RuntimeError("端口跳跃范围格式应为 起始端口-结束端口，例如 20000-30000")

        if protocol == "anytls":
            ib = {
                "type": "anytls", "tag": tag, "listen": listen, "listen_port": port,
                "users": [{"name": "quack", "password": pw}],
                "tls": {"enabled": True, "server_name": sni, "certificate_path": crt, "key_path": key},
            }
        elif protocol == "hysteria2":
            ib = {
                "type": "hysteria2", "tag": tag, "listen": listen, "listen_port": port,
                "users": [{"name": "quack", "password": pw}],
                "tls": {"enabled": True, "server_name": sni, "certificate_path": crt, "key_path": key},
            }
        else:  # tuic
            _, uuid, _ = run_cmd(["xray", "uuid"])
            uuid = uuid or str(secrets.token_hex(16))
            ib = {
                "type": "tuic", "tag": tag, "listen": listen, "listen_port": port,
                "users": [{"name": "quack", "uuid": uuid, "password": pw}],
                "congestion_control": "bbr",
                "tls": {"enabled": True, "server_name": sni, "alpn": ["h3"], "certificate_path": crt, "key_path": key},
            }
        sb_cfg["inbounds"].append(ib)
        _apply_socks5_to_singbox_cfg(sb_cfg, get_socks5_cfg())
        save_singbox_cfg(sb_cfg)
        set_meta(
            tag,
            remark=remark or f"QuackUI-{protocol.upper()}-{port}",
            public_key="",
            enabled=1,
            disabled_json="",
            engine="sing-box",
            hop_range=hop_range if protocol == "hysteria2" else "",
        )
        sync_nftables()
        return tag

    if protocol not in ("vless", "vmess", "trojan", "shadowsocks"):
        raise RuntimeError("不支持的协议")
    if transport not in ("raw", "ws", "xhttp", "grpc"):
        raise RuntimeError("不支持的传输方式，请选择 raw / ws / xhttp / grpc")
    if security not in ("none", "reality", "tls"):
        raise RuntimeError("不支持的安全层，请选择 none / reality / tls")
    if protocol == "vmess" and security == "reality":
        raise RuntimeError("VMess 不支持 Reality，请选择 None（配合反代/CDN）或切换协议为 VLESS")
    if protocol == "shadowsocks":
        transport, security = "raw", "none"

    cfg = read_xray_cfg()
    existing_tags = {ib.get("tag") for ib in cfg.get("inbounds", [])} | set(get_meta_map().keys())
    tag = f"{protocol[:2]}-{secrets.token_hex(3)}"
    while tag in existing_tags:
        tag = f"{protocol[:2]}-{secrets.token_hex(3)}"

    if listen_type == "ipv6":
        _, _, _, v6_addr = detect_default_v6_iface_and_prefix()
        listen = v6_addr
    elif listen_type == "ipv4":
        listen = "0.0.0.0"
    elif listen_type == "dual":
        listen = "::"
    else:
        listen = "127.0.0.1"

    for ib in cfg.get("inbounds", []):
        if ib.get("port") == port and ib.get("listen") in (listen, "::", "0.0.0.0"):
            raise RuntimeError(f"端口 {port} 已被节点 {ib.get('tag')} 占用，请更换端口")

    pub = ""
    if protocol in ("vless", "vmess"):
        code, uuid, err = run_cmd(["xray", "uuid"])
        if code != 0 or not uuid:
            raise RuntimeError(f"生成 UUID 失败: {err}")
        if protocol == "vless":
            client = {"id": uuid}
            if transport == "raw" and security == "reality":
                client["flow"] = "xtls-rprx-vision"
            settings = {"clients": [client], "decryption": "none"}
        else:
            settings = {"clients": [{"id": uuid}]}
    elif protocol == "trojan":
        pw = secrets.token_urlsafe(16)
        settings = {"clients": [{"password": pw}]}
    else:  # shadowsocks
        method = (payload.get("ss_method") or "2022-blake3-aes-128-gcm").strip()
        if method not in (
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
        ):
            raise RuntimeError("不支持的 Shadowsocks 加密方式")
        if method == "2022-blake3-aes-128-gcm":
            ss_pw = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        elif method == "2022-blake3-aes-256-gcm":
            ss_pw = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        else:
            ss_pw = secrets.token_urlsafe(18)
        settings = {"method": method, "password": ss_pw, "network": "tcp,udp"}

    stream = {"network": transport}
    if transport == "ws":
        p = (payload.get("path") or f"/{secrets.token_hex(6)}").strip()
        stream["wsSettings"] = {"path": p if p.startswith("/") else "/" + p}
    elif transport == "xhttp":
        p = (payload.get("path") or f"/{secrets.token_hex(6)}").strip()
        stream["xhttpSettings"] = {"path": p if p.startswith("/") else "/" + p, "mode": "auto", "xPaddingBytes": "100-1000"}
    elif transport == "grpc":
        svc = (payload.get("path") or f"svc-{secrets.token_hex(4)}").strip().lstrip("/")
        stream["grpcSettings"] = {"serviceName": svc}

    if security == "reality":
        sni = (payload.get("sni") or "www.berkeley.edu").strip().lower()
        if not re.match(r"^[a-z0-9.-]{3,100}$", sni) or "." not in sni:
            raise RuntimeError("SNI 域名格式不正确")
        priv, pub = generate_x25519()
        sid = secrets.token_hex(8)
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "show": False,
            "target": f"{sni}:443",
            "xver": 0,
            "serverNames": [sni],
            "privateKey": priv,
            "shortIds": [sid],
        }
    elif security == "tls":
        sni = (payload.get("sni") or "").strip().lower()
        cert_file = (payload.get("cert_file") or "/etc/nginx/cert/fullchain.pem").strip()
        key_file = (payload.get("key_file") or "/etc/nginx/cert/key.pem").strip()
        if not (os.path.exists(cert_file) and os.path.exists(key_file)):
            raise RuntimeError(f"未找到 TLS 证书文件 ({cert_file})，若通过 Nginx/CDN 终结 TLS 请把安全层设为 None")
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": sni,
            "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
        }
    else:
        stream["security"] = "none"

    ib = {
        "tag": tag,
        "listen": listen,
        "port": port,
        "protocol": protocol,
        "settings": settings,
        "streamSettings": stream,
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
    }

    cfg["inbounds"].append(ib)
    save_xray_cfg(cfg)
    default_remark = f"QuackUI-{protocol.upper()}-{security if security != 'none' else transport}-{port}"
    set_meta(tag, remark=remark or default_remark, public_key=pub, enabled=1, disabled_json="", engine="xray")
    sync_nftables()
    return tag


def toggle_node(tag):
    meta_map = get_meta_map()
    meta = meta_map.get(tag, {})
    if meta.get("engine") == "sing-box":
        sb_cfg = read_singbox_cfg()
        inbounds = sb_cfg.get("inbounds", [])
        idx = next((i for i, ib in enumerate(inbounds) if ib.get("tag") == tag), None)
        if idx is not None:
            ib = inbounds.pop(idx)
            save_singbox_cfg(sb_cfg)
            set_meta(tag, enabled=0, disabled_json=json.dumps(ib, ensure_ascii=False))
            sync_nftables()
            return False
        if not meta.get("disabled_json"):
            raise RuntimeError("找不到该节点配置")
        inbounds.append(json.loads(meta["disabled_json"]))
        save_singbox_cfg(sb_cfg)
        set_meta(tag, enabled=1, disabled_json="")
        sync_nftables()
        return True

    cfg = read_xray_cfg()
    inbounds = cfg.get("inbounds", [])
    idx = next((i for i, ib in enumerate(inbounds) if ib.get("tag") == tag), None)

    if idx is not None:
        ib = inbounds.pop(idx)
        save_xray_cfg(cfg)
        set_meta(tag, enabled=0, disabled_json=json.dumps(ib, ensure_ascii=False))
        sync_nftables()
        return False
    else:
        if not meta or not meta.get("disabled_json"):
            raise RuntimeError("找不到该节点的配置")
        ib = json.loads(meta["disabled_json"])
        inbounds.append(ib)
        save_xray_cfg(cfg)
        set_meta(tag, enabled=1, disabled_json="")
        sync_nftables()
        return True


def delete_node(tag):
    if tag == "api":
        raise RuntimeError("不能删除内部 API 入站")
    meta = get_meta_map().get(tag, {})
    if meta.get("engine") == "sing-box":
        sb_cfg = read_singbox_cfg()
        sb_cfg["inbounds"] = [ib for ib in sb_cfg.get("inbounds", []) if ib.get("tag") != tag]
        save_singbox_cfg(sb_cfg)
        for ext in (".crt", ".key"):
            p = os.path.join(CERT_DIR, f"{tag}{ext}")
            if os.path.exists(p):
                os.remove(p)
        del_meta(tag)
        sync_nftables()
        return

    cfg = read_xray_cfg()
    cfg["inbounds"] = [ib for ib in cfg.get("inbounds", []) if ib.get("tag") != tag]
    save_xray_cfg(cfg)
    del_meta(tag)
    sync_nftables()


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

    meta = get_meta_map().get(tag, {})
    old_v6 = ""
    if meta.get("engine") == "sing-box":
        sb_cfg = read_singbox_cfg()
        ib = next((x for x in sb_cfg.get("inbounds", []) if x.get("tag") == tag), None)
        if not ib:
            raise RuntimeError("未找到运行中的 sing-box 节点")
        old_v6 = ib.get("listen", "")
        ib["listen"] = new_v6
        save_singbox_cfg(sb_cfg)
    else:
        cfg = read_xray_cfg()
        ib = next((x for x in cfg.get("inbounds", []) if x.get("tag") == tag), None)
        if not ib:
            raise RuntimeError("未找到运行中的 Xray 节点")
        old_v6 = ib["listen"]
        ib["listen"] = new_v6
        save_xray_cfg(cfg)

    all_listens = {x.get("listen") for x in read_xray_cfg().get("inbounds", [])} | {
        x.get("listen") for x in read_singbox_cfg().get("inbounds", [])
    }
    if old_v6 != base_addr and old_v6 != new_v6 and ":" in old_v6 and old_v6 != "::":
        if old_v6 not in all_listens:
            run_cmd(["ip", "-6", "addr", "del", f"{old_v6}/{plen}", "dev", iface])

    if tag == "reality-in":
        info = read_node_info()
        info["REALITY_V6"] = new_v6
        write_node_info(info)
    sync_nftables()
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
    meta = get_meta_map().get(tag, {})
    if meta.get("engine") == "sing-box":
        sb_cfg = read_singbox_cfg()
        ib = next((x for x in sb_cfg.get("inbounds", []) if x.get("tag") == tag), None)
        if not ib:
            raise RuntimeError("未找到运行中的 sing-box 节点")
        new_pw = secrets.token_urlsafe(16)
        ib["users"][0]["password"] = new_pw
        if ib.get("type") == "tuic":
            _, new_uuid, _ = run_cmd(["xray", "uuid"])
            if new_uuid:
                ib["users"][0]["uuid"] = new_uuid
        save_singbox_cfg(sb_cfg)
        return new_pw, ""

    cfg = read_xray_cfg()
    ib = next((x for x in cfg.get("inbounds", []) if x.get("tag") == tag), None)
    if not ib:
        raise RuntimeError("未找到运行中的目标节点")
    proto = ib.get("protocol", "vless")
    new_sid = secrets.token_hex(8)
    new_id = ""

    if proto in ("vless", "vmess"):
        code, new_uuid, err = run_cmd(["xray", "uuid"])
        if code != 0 or not new_uuid:
            raise RuntimeError(f"生成 UUID 失败: {err}")
        ib["settings"]["clients"][0]["id"] = new_uuid
        new_id = new_uuid
    elif proto == "trojan":
        new_id = secrets.token_urlsafe(16)
        ib["settings"]["clients"][0]["password"] = new_id
    elif proto == "shadowsocks":
        method = ib["settings"].get("method", "")
        if method == "2022-blake3-aes-128-gcm":
            new_id = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        elif method == "2022-blake3-aes-256-gcm":
            new_id = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        else:
            new_id = secrets.token_urlsafe(18)
        ib["settings"]["password"] = new_id

    if ib.get("streamSettings", {}).get("security") == "reality":
        ib["streamSettings"]["realitySettings"]["shortIds"] = [new_sid]
    save_xray_cfg(cfg)

    if tag == "reality-in":
        info = read_node_info()
        info["REALITY_UUID"] = new_id
        info["REALITY_SID"] = new_sid
        write_node_info(info)
    return new_id, new_sid


def rename_node(tag, new_remark):
    new_remark = (new_remark or "").strip()[:40]
    if not new_remark:
        raise RuntimeError("备注名称不能为空")
    set_meta(tag, remark=new_remark)
    return new_remark


def set_node_limits(tag, quota_gb, expire_date):
    q = max(0.0, float(quota_gb or 0))
    exp = (expire_date or "").strip()
    if exp and not re.match(r"^\d{4}-\d{2}-\d{2}$", exp):
        raise RuntimeError("到期日期格式应为 YYYY-MM-DD")
    set_meta(tag, quota_gb=q, expire_date=exp)


def reset_node_traffic(tag):
    with DB_LOCK, db_conn() as conn:
        conn.execute("DELETE FROM daily_traffic WHERE tag=?", (tag,))


def add_node_client(tag, name):
    name = re.sub(r"[^a-zA-Z0-9._-]", "", (name or "").strip())[:24] or f"dev-{secrets.token_hex(2)}"
    meta = get_meta_map().get(tag, {})
    if meta.get("engine") == "sing-box":
        sb_cfg = read_singbox_cfg()
        ib = next((x for x in sb_cfg.get("inbounds", []) if x.get("tag") == tag), None)
        if not ib:
            raise RuntimeError("未找到运行中的 sing-box 节点")
        pw = secrets.token_urlsafe(14)
        u = {"name": name, "password": pw}
        if ib.get("type") == "tuic":
            _, uuid, _ = run_cmd(["xray", "uuid"])
            u["uuid"] = uuid or str(secrets.token_hex(16))
        ib.setdefault("users", []).append(u)
        save_singbox_cfg(sb_cfg)
        return name

    cfg = read_xray_cfg()
    ib = next((x for x in cfg.get("inbounds", []) if x.get("tag") == tag), None)
    if not ib:
        raise RuntimeError("未找到运行中的 Xray 节点")
    proto = ib.get("protocol", "vless")
    if proto == "shadowsocks":
        raise RuntimeError("Shadowsocks 单端口模式不支持多子用户，请新建节点")
    clients = ib["settings"].setdefault("clients", [])
    if proto in ("vless", "vmess"):
        code, uuid, err = run_cmd(["xray", "uuid"])
        if code != 0 or not uuid:
            raise RuntimeError(f"生成 UUID 失败: {err}")
        c = {"id": uuid, "email": name}
        if proto == "vless" and ib.get("streamSettings", {}).get("network") == "raw" and ib.get("streamSettings", {}).get("security") == "reality":
            c["flow"] = "xtls-rprx-vision"
        clients.append(c)
    elif proto == "trojan":
        clients.append({"password": secrets.token_urlsafe(14), "email": name})
    save_xray_cfg(cfg)
    return name


def del_node_client(tag, index):
    idx = int(index)
    meta = get_meta_map().get(tag, {})
    if meta.get("engine") == "sing-box":
        sb_cfg = read_singbox_cfg()
        ib = next((x for x in sb_cfg.get("inbounds", []) if x.get("tag") == tag), None)
        if not ib:
            raise RuntimeError("未找到节点")
        users = ib.get("users", [])
        if len(users) <= 1:
            raise RuntimeError("每个节点至少保留 1 个用户")
        if not (0 <= idx < len(users)):
            raise RuntimeError("用户索引无效")
        users.pop(idx)
        save_singbox_cfg(sb_cfg)
        return

    cfg = read_xray_cfg()
    ib = next((x for x in cfg.get("inbounds", []) if x.get("tag") == tag), None)
    if not ib:
        raise RuntimeError("未找到节点")
    clients = ib.get("settings", {}).get("clients", [])
    if len(clients) <= 1:
        raise RuntimeError("每个节点至少保留 1 个用户")
    if not (0 <= idx < len(clients)):
        raise RuntimeError("用户索引无效")
    clients.pop(idx)
    save_xray_cfg(cfg)


def build_subscription_bundle():
    cfg = read_xray_cfg()
    tr = get_traffic_summary()
    nodes = [n for n in list_all_nodes(cfg, tr["by_tag"]) if n["enabled"] and n.get("uri")]
    uris = [n["uri"] for n in nodes]
    b64 = base64.b64encode("\n".join(uris).encode("utf-8")).decode("ascii")
    clash_proxies = "\n".join(n["clash_yaml"] for n in nodes if n.get("clash_yaml"))
    clash_names = "\n".join(f"      - {n['remark']}" for n in nodes if n.get("clash_yaml"))
    clash_full = (
        "proxies:\n" + clash_proxies + "\n\n"
        "proxy-groups:\n"
        "  - name: QuackUI-Auto\n"
        "    type: url-test\n"
        "    url: https://www.gstatic.com/generate_204\n"
        "    interval: 300\n"
        "    proxies:\n" + clash_names + "\n"
    )
    return {"count": len(uris), "raw_uris": "\n".join(uris), "base64": b64, "clash_yaml": clash_full}


def get_raw_config(engine):
    if engine == "singbox":
        return json.dumps(read_singbox_cfg(), indent=2, ensure_ascii=False)
    return json.dumps(read_xray_cfg(), indent=2, ensure_ascii=False)


def save_raw_config(engine, text):
    try:
        parsed = json.loads(text)
    except Exception as e:
        raise RuntimeError(f"JSON 语法错误: {e}")
    if engine == "singbox":
        save_singbox_cfg(parsed)
    else:
        save_xray_cfg(parsed)
    sync_nftables()


def gfw_tcp_probe(target_ip, port):
    """Use Globalping open probe network to test TCP port reachability from China (CN) vs US."""
    try:
        target_norm = str(ipaddress.ip_address(target_ip))
    except Exception:
        return {"status": "unknown", "summary": "无效的目标 IP", "cn_probes": [], "us_probes": []}

    body = json.dumps({
        "type": "mtr",
        "target": target_norm,
        "locations": [{"country": "CN", "limit": 4}, {"country": "US", "limit": 2}],
        "measurementOptions": {"protocol": "TCP", "port": int(port), "packets": 2},
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            "https://api.globalping.io/v1/measurements",
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": f"QuackUI/{VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            mid = json.loads(r.read().decode("utf-8")).get("id")
        if not mid:
            return {"status": "unknown", "summary": "探针创建失败", "cn_probes": [], "us_probes": []}

        res_data = None
        for _ in range(14):
            time.sleep(1.5)
            with urllib.request.urlopen(f"https://api.globalping.io/v1/measurements/{mid}", timeout=10) as r:
                d = json.loads(r.read().decode("utf-8"))
            if d.get("status") == "finished":
                res_data = d
                break
        if not res_data:
            return {"status": "unknown", "summary": "探针响应超时", "cn_probes": [], "us_probes": []}

        cn_probes, us_probes = [], []
        for item in res_data.get("results", []):
            pr = item.get("probe", {})
            hops = item.get("result", {}).get("hops", [])
            reached = False
            avg_ms = None
            for h in hops:
                addr = h.get("resolvedAddress") or ""
                try:
                    if addr and str(ipaddress.ip_address(addr)) == target_norm and h.get("stats", {}).get("rcv", 0) > 0:
                        reached = True
                        avg_ms = round(float(h["stats"].get("avg", 0)), 1)
                        break
                except Exception:
                    pass
            entry = {
                "city": pr.get("city") or pr.get("country") or "Unknown",
                "network": (pr.get("network") or "")[:36],
                "reached": reached,
                "avg_ms": avg_ms,
            }
            if pr.get("country") == "CN":
                cn_probes.append(entry)
            else:
                us_probes.append(entry)

        cn_ok = sum(1 for x in cn_probes if x["reached"])
        cn_tot = len(cn_probes)
        if cn_tot == 0:
            status, summary = "unknown", "暂无可用的中国大陆探针"
        elif cn_ok == cn_tot:
            status, summary = "ok", f"未检测到 GFW 阻断（中国大陆 {cn_ok}/{cn_tot} 节点 TCP:{port} 正常可达）"
        elif cn_ok > 0:
            status, summary = "warn", f"部分地区受限或丢包（中国大陆 {cn_ok}/{cn_tot} 节点 TCP:{port} 可达）"
        else:
            status, summary = "blocked", f"疑似被 GFW 阻断（中国大陆 0/{cn_tot} 节点可达 TCP:{port}，建议更换 IPv6 地址或端口）"

        return {
            "status": status,
            "summary": summary,
            "target": f"{target_norm}:{port}",
            "cn_ok": cn_ok,
            "cn_total": cn_tot,
            "cn_probes": cn_probes,
            "us_probes": us_probes,
        }
    except Exception as e:
        return {"status": "unknown", "summary": f"探针暂不可用: {str(e)[:80]}", "cn_probes": [], "us_probes": []}


def self_check_node(tag="reality-in", include_gfw=True):
    """5-dimension node health check: proxy E2E, outbound IP, SNI health, CN block rule, GFW TCP probe."""
    cfg = read_xray_cfg()
    meta_map = get_meta_map()
    ib = next((x for x in cfg.get("inbounds", []) if x.get("tag") == tag), None)
    if not ib:
        ib = next((x for x in cfg.get("inbounds", []) if x.get("streamSettings", {}).get("security") == "reality"), None)
    if not ib:
        raise RuntimeError("没有可自检的 Reality 节点")
    tag = ib["tag"]
    rs = ib["streamSettings"]["realitySettings"]
    sni = rs["serverNames"][0]
    pub = meta_map.get(tag, {}).get("public_key") or read_node_info().get("REALITY_PUB", "")
    listen = ib["listen"]
    probe_ip = detect_public_ipv4() if listen in ("0.0.0.0", "::", "") else listen
    local_addr = "127.0.0.1" if listen in ("0.0.0.0", "::", "") else listen

    # 1. Start GFW probe in background thread while running local E2E checks in parallel
    gfw_holder = {}
    t_gfw = None
    if include_gfw:
        def _run_gfw():
            gfw_holder["res"] = gfw_tcp_probe(probe_ip, ib["port"])
        t_gfw = threading.Thread(target=_run_gfw, daemon=True)
        t_gfw.start()

    # 2. SNI health check (TLS 1.3 + HTTP/2)
    sc, sout, _ = run_cmd([
        "curl", "-sS", "--max-time", "5", "--tlsv1.3", "--http2",
        "-o", "/dev/null", "-w", "%{http_code} %{time_appconnect}", f"https://{sni}/"
    ], timeout=7)
    s_parts = sout.split()
    sni_code = s_parts[0] if s_parts else "000"
    sni_ms = int(float(s_parts[1]) * 1000) if len(s_parts) > 1 else 0
    sni_ok = sc == 0 and sni_code in ("200", "301", "302", "307", "308")

    # 3. Local Xray E2E check: Google 204 + Outbound IP + CN block rule check
    tmp_cfg = "/tmp/quackui_selfcheck.json"
    client_cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": 10899, "protocol": "socks"}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": local_addr,
                "port": ib["port"],
                "users": [{"id": ib["settings"]["clients"][0]["id"], "encryption": "none", "flow": "xtls-rprx-vision"}]
            }]},
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "serverName": sni,
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
        _, cn_out, _ = run_cmd([
            "curl", "-s", "--max-time", "4", "-x", "socks5h://127.0.0.1:10899",
            "-o", "/dev/null", "-w", "%{http_code}", "https://www.baidu.com/"
        ], timeout=6)
        parts = g_out.split()
        code_str = parts[0] if parts else "000"
        ms = int(float(parts[1]) * 1000) if len(parts) > 1 else 0
        proxy_ok = c1 == 0 and code_str == "204"
        out_ip = ip_out.strip() or "-"
        out_is_v4 = "." in out_ip and ":" not in out_ip
        cn_blocked = cn_out.strip() in ("", "000")
    finally:
        p.terminate()
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
        if os.path.exists(tmp_cfg):
            os.remove(tmp_cfg)

    if t_gfw:
        t_gfw.join(timeout=24)
    gfw_res = gfw_holder.get("res", {"status": "unknown", "summary": "未执行 GFW 检测", "cn_probes": [], "us_probes": []})

    return {
        "ok": proxy_ok and gfw_res.get("status") != "blocked",
        "tag": tag,
        "proxy": {"ok": proxy_ok, "http_code": code_str, "latency_ms": ms},
        "outbound": {"ip": out_ip, "is_v4": out_is_v4},
        "sni": {"domain": sni, "ok": sni_ok, "http_code": sni_code, "handshake_ms": sni_ms},
        "cn_block": {"blocked": cn_blocked, "http_code": cn_out.strip() or "000"},
        "gfw": gfw_res,
        "is_v6": ":" in probe_ip,
    }


def get_xray_version():
    _, out, _ = run_cmd(["xray", "version"], timeout=3)
    if out:
        parts = out.splitlines()[0].split()
        if len(parts) >= 2:
            return parts[1]
    return "-"


def fetch_xray_releases(force=False):
    """Fetch recent Xray-core releases from GitHub API with 10-minute cache."""
    now = time.time()
    if not force and RELEASES_CACHE["items"] and (now - RELEASES_CACHE["ts"] < 600):
        return RELEASES_CACHE["items"]
    req = urllib.request.Request(
        "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=20",
        headers={"User-Agent": f"QuackUI/{VERSION}", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = json.loads(resp.read().decode("utf-8"))
    items = []
    for r in raw:
        tag = r.get("tag_name", "")
        if not tag:
            continue
        items.append({
            "version": tag.lstrip("v"),
            "tag": tag,
            "date": (r.get("published_at") or "")[:10],
            "prerelease": bool(r.get("prerelease")),
        })
    RELEASES_CACHE["ts"] = now
    RELEASES_CACHE["items"] = items
    return items


def switch_xray_version(target_ver):
    """Upgrade or downgrade Xray-core safely with automatic rollback on failure."""
    target_ver = (target_ver or "").strip()
    if target_ver != "latest":
        target_ver = target_ver.lstrip("v")
        if not re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$", target_ver):
            raise RuntimeError("版本号格式不正确")

    xray_bin = "/usr/local/bin/xray"
    bak_bin = "/usr/local/bin/xray.bak"
    old_ver = get_xray_version()
    if os.path.exists(xray_bin):
        shutil.copy2(xray_bin, bak_bin)

    install_cmd = (
        'bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install'
        if target_ver == "latest"
        else f'bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version {target_ver}'
    )
    code, _, err = run_cmd(["bash", "-c", install_cmd], timeout=120)
    if code != 0:
        if os.path.exists(bak_bin):
            shutil.copy2(bak_bin, xray_bin)
            run_cmd(["systemctl", "restart", "xray"])
        raise RuntimeError(f"安装 Xray 失败，已保留原版本 {old_ver}: {err[-200:]}")

    # Validate existing config and restart; auto-rollback if incompatible
    tc, _, terr = run_cmd(["xray", "run", "-test", "-c", XRAY_CFG], timeout=10)
    rc = 1
    if tc == 0:
        rc, _, _ = run_cmd(["systemctl", "restart", "xray"], timeout=15)
        time.sleep(1)
        _, st, _ = run_cmd(["systemctl", "is-active", "xray"], timeout=5)
        if st != "active":
            rc = 1

    if tc != 0 or rc != 0:
        if os.path.exists(bak_bin):
            shutil.copy2(bak_bin, xray_bin)
            run_cmd(["systemctl", "restart", "xray"], timeout=15)
        raise RuntimeError(f"目标版本与当前配置不兼容，已自动回滚到 {old_ver}: {terr[-180:]}")

    return {"old_version": old_ver, "new_version": get_xray_version()}


def update_geodata():
    cmd = 'bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata'
    code, _, err = run_cmd(["bash", "-c", cmd], timeout=90)
    if code != 0:
        raise RuntimeError(f"更新 GeoData 失败: {err[-180:]}")
    run_cmd(["systemctl", "restart", "xray"], timeout=15)


def stream_self_check(tag, emit):
    """Run 5-dimension health check step-by-step and emit SSE events in real time."""
    cfg = read_xray_cfg()
    meta_map = get_meta_map()
    ib = next((x for x in cfg.get("inbounds", []) if x.get("tag") == tag), None)
    if not ib:
        ib = next((x for x in cfg.get("inbounds", []) if x.get("streamSettings", {}).get("security") == "reality"), None)
    if not ib:
        emit("error", {"err": "没有可自检的 Reality 节点"})
        return

    tag = ib["tag"]
    rs = ib["streamSettings"]["realitySettings"]
    sni = rs["serverNames"][0]
    pub = meta_map.get(tag, {}).get("public_key") or read_node_info().get("REALITY_PUB", "")
    listen = ib["listen"]
    port = ib["port"]
    probe_ip = detect_public_ipv4() if listen in ("0.0.0.0", "::", "") else listen
    local_addr = "127.0.0.1" if listen in ("0.0.0.0", "::", "") else listen
    is_v6 = ":" in probe_ip

    emit("start", {"tag": tag, "target": f"{probe_ip}:{port}", "sni": sni, "is_v6": is_v6})

    # Kick off Globalping GFW probe in background immediately so it runs concurrently
    gfw_holder = {}
    def _bg_gfw():
        gfw_holder["res"] = gfw_tcp_probe(probe_ip, port)
    t_gfw = threading.Thread(target=_bg_gfw, daemon=True)
    t_gfw.start()

    # Step 1: SNI health
    emit("step", {"id": "sni", "state": "running", "log": f"[1/5] 正在检测伪装目标 {sni}:443 (TLS 1.3 + HTTP/2)..."})
    sc, sout, _ = run_cmd([
        "curl", "-sS", "--max-time", "5", "--tlsv1.3", "--http2",
        "-o", "/dev/null", "-w", "%{http_code} %{time_appconnect}", f"https://{sni}/"
    ], timeout=7)
    s_parts = sout.split()
    sni_code = s_parts[0] if s_parts else "000"
    sni_ms = int(float(s_parts[1]) * 1000) if len(s_parts) > 1 else 0
    sni_ok = sc == 0 and sni_code in ("200", "301", "302", "307", "308")
    emit("step", {
        "id": "sni", "state": "ok" if sni_ok else "fail",
        "detail": f"TLS 1.3 + H2 · HTTP {sni_code} · {sni_ms} ms" if sni_ok else f"HTTP {sni_code}",
        "log": f"[1/5] SNI {sni} -> {'通过' if sni_ok else '异常'} (HTTP {sni_code}, {sni_ms}ms)"
    })

    # Start temporary local Xray Reality client for steps 2, 3, 4
    tmp_cfg = "/tmp/quackui_selfcheck_sse.json"
    client_cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": 10898, "protocol": "socks"}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": local_addr, "port": port,
                "users": [{"id": ib["settings"]["clients"][0]["id"], "encryption": "none", "flow": "xtls-rprx-vision"}]
            }]},
            "streamSettings": {
                "network": "raw", "security": "reality",
                "realitySettings": {"serverName": sni, "fingerprint": "chrome", "publicKey": pub, "shortId": rs["shortIds"][0]}
            }
        }]
    }
    with open(tmp_cfg, "w", encoding="utf-8") as f:
        json.dump(client_cfg, f)
    p = subprocess.Popen(["xray", "run", "-c", tmp_cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy_ok = False
    try:
        # Step 2: Reality E2E -> Google 204
        emit("step", {"id": "proxy", "state": "running", "log": f"[2/5] 启动本机 Reality 客户端连接 {local_addr}:{port} -> 请求 Google 204..."})
        time.sleep(1.3)
        c1, g_out, _ = run_cmd([
            "curl", "-s", "--max-time", "8", "-x", "socks5h://127.0.0.1:10898",
            "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "https://www.google.com/generate_204"
        ], timeout=10)
        parts = g_out.split()
        code_str = parts[0] if parts else "000"
        ms = int(float(parts[1]) * 1000) if len(parts) > 1 else 0
        proxy_ok = c1 == 0 and code_str == "204"
        emit("step", {
            "id": "proxy", "state": "ok" if proxy_ok else "fail",
            "detail": f"HTTP 204 · {ms} ms" if proxy_ok else f"HTTP {code_str}",
            "log": f"[2/5] Reality 代理访问 Google -> {'通过' if proxy_ok else '失败'} (HTTP {code_str}, {ms}ms)"
        })

        # Step 3: Outbound IP check
        emit("step", {"id": "outbound", "state": "running", "log": "[3/5] 正在通过代理查询实际出口 IP (ifconfig.co)..."})
        _, ip_out, _ = run_cmd(["curl", "-s", "--max-time", "6", "-x", "socks5h://127.0.0.1:10898", "https://ifconfig.co"], timeout=8)
        out_ip = ip_out.strip() or "-"
        out_is_v4 = "." in out_ip and ":" not in out_ip
        emit("step", {
            "id": "outbound", "state": "ok" if out_ip != "-" else "fail",
            "detail": f"{out_ip} ({'纯 IPv4' if out_is_v4 else 'IPv6/其他'})",
            "log": f"[3/5] 实际出口 IP -> {out_ip} ({'IPv4' if out_is_v4 else 'Non-IPv4'})"
        })

        # Step 4: CN block rule check
        emit("step", {"id": "cn_block", "state": "running", "log": "[4/5] 正在试连 www.baidu.com 校验服务端国内拦截规则..."})
        _, cn_out, _ = run_cmd([
            "curl", "-s", "--max-time", "4", "-x", "socks5h://127.0.0.1:10898",
            "-o", "/dev/null", "-w", "%{http_code}", "https://www.baidu.com/"
        ], timeout=6)
        cn_blocked = cn_out.strip() in ("", "000")
        emit("step", {
            "id": "cn_block", "state": "ok" if cn_blocked else "warn",
            "detail": "拦截生效 (000)" if cn_blocked else f"未拦截 (HTTP {cn_out.strip()})",
            "log": f"[4/5] 国内分流拦截校验 -> {'已拦截 (安全)' if cn_blocked else '未拦截 (建议开启)'}"
        })
    finally:
        p.terminate()
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
        if os.path.exists(tmp_cfg):
            os.remove(tmp_cfg)

    # Step 5: Wait for Globalping CN multi-city TCP port probe
    emit("step", {"id": "gfw", "state": "running", "log": f"[5/5] 正在等待中国大陆多城市探针对 {probe_ip}:{port} 的 TCP 端口检测结果..."})
    t_gfw.join(timeout=24)
    gfw = gfw_holder.get("res", {"status": "unknown", "summary": "探针超时", "cn_probes": []})
    g_state = "ok" if gfw.get("status") == "ok" else ("warn" if gfw.get("status") in ("warn", "unknown") else "fail")
    emit("step", {
        "id": "gfw", "state": g_state, "gfw": gfw,
        "detail": gfw.get("summary", "-"),
        "log": f"[5/5] GFW 阻断检测完成 -> {gfw.get('summary', '-')}"
    })
    emit("done", {"ok": proxy_ok and gfw.get("status") != "blocked", "tag": tag, "is_v6": is_v6, "gfw": gfw})


def build_backup_tar_gz():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p, arc in [
            (XRAY_CFG, "xray-config.json"),
            (SB_CFG, "singbox.json"),
            (NFT_CFG, "nftables.conf"),
            (NODE_INFO, "node-info.txt"),
            (DB_PATH, "quackui.db"),
            (CUSTOM_V6_IFACE, "60-custom-v6"),
        ]:
            if os.path.exists(p):
                tar.add(p, arcname=arc)
        if os.path.isdir(CERT_DIR):
            tar.add(CERT_DIR, arcname="certs")
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
    sb_ver = get_singbox_version()
    if sb_ver:
        _, sbo, _ = run_cmd(["systemctl", "is-active", "quackui-singbox"], timeout=3)
        svcs["singbox"] = sbo or "inactive"
    else:
        svcs["singbox"] = "not-installed"

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
    _, bbr_out, _ = run_cmd(["sysctl", "-n", "net.ipv4.tcp_congestion_control"], timeout=2)
    _, kern_out, _ = run_cmd(["uname", "-r"], timeout=2)
    os_name = "Linux"
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
                    break
    pub_v4 = detect_public_ipv4()
    try:
        _, _, _, pub_v6 = detect_default_v6_iface_and_prefix()
    except Exception:
        pub_v6 = "-"

    return {
        "version": VERSION,
        "xray_version": xray_ver_short,
        "singbox_version": sb_ver or "-",
        "os": os_name,
        "kernel": kern_out or "-",
        "tcp_cc": bbr_out or "-",
        "ipv4": pub_v4,
        "ipv6": pub_v6,
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
                "socks5": get_socks5_cfg(),
            })
        elif path == "/api/logs":
            _, xray_log, _ = run_cmd(["journalctl", "-u", "xray", "-n", "40", "--no-pager"], timeout=5)
            _, sb_log, _ = run_cmd(["journalctl", "-u", "quackui-singbox", "-n", "40", "--no-pager"], timeout=5)
            _, f2b_log, _ = run_cmd(["fail2ban-client", "status", "sshd"], timeout=4)
            _, nft_log, _ = run_cmd(["nft", "list", "ruleset"], timeout=4)
            self._send_json({"xray": xray_log, "singbox": sb_log or "sing-box 未运行或暂无日志", "fail2ban": f2b_log, "firewall": nft_log})
        elif path == "/api/xray/releases":
            force = "force=1" in self.path
            try:
                items = fetch_xray_releases(force=force)
                self._send_json({
                    "ok": True,
                    "current": get_xray_version(),
                    "has_backup": os.path.exists("/usr/local/bin/xray.bak"),
                    "releases": items,
                })
            except Exception as e:
                self._send_json({"ok": False, "current": get_xray_version(), "err": str(e)}, 502)
        elif path == "/api/self-check/stream":
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            tag = (qs.get("tag") or ["reality-in"])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            def emit(ev, payload):
                chunk = f"event: {ev}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")
                self.wfile.write(chunk)
                self.wfile.flush()

            try:
                stream_self_check(tag, emit)
            except Exception as e:
                try:
                    emit("error", {"err": str(e)})
                except Exception:
                    pass
        elif path == "/api/subscription":
            self._send_json({"ok": True, "data": build_subscription_bundle()})
        elif path == "/api/raw-config":
            from urllib.parse import parse_qs, urlparse
            eng = (parse_qs(urlparse(self.path).query).get("engine") or ["xray"])[0]
            self._send_json({"ok": True, "engine": eng, "content": get_raw_config(eng)})
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
            elif path == "/api/nodes/rename":
                nr = rename_node(data.get("tag", ""), data.get("remark", ""))
                self._send_json({"ok": True, "msg": f"节点备注已更新为 {nr}"})
            elif path == "/api/nodes/limits":
                set_node_limits(data.get("tag", ""), data.get("quota_gb", 0), data.get("expire_date", ""))
                self._send_json({"ok": True, "msg": "节点流量限额与到期时间已更新"})
            elif path == "/api/nodes/reset-traffic":
                reset_node_traffic(data.get("tag", ""))
                self._send_json({"ok": True, "msg": "节点累计流量已清零"})
            elif path == "/api/nodes/clients/add":
                cname = add_node_client(data.get("tag", ""), data.get("name", ""))
                self._send_json({"ok": True, "msg": f"已添加子用户 {cname}"})
            elif path == "/api/nodes/clients/delete":
                del_node_client(data.get("tag", ""), data.get("index", -1))
                self._send_json({"ok": True, "msg": "已移除该子用户"})
            elif path == "/api/raw-config":
                save_raw_config(data.get("engine", "xray"), data.get("content", ""))
                self._send_json({"ok": True, "msg": f"{data.get('engine', 'xray')} 配置校验通过并已生效"})
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
            elif path == "/api/socks5/test":
                res = test_socks5_connectivity(
                    data.get("host", ""),
                    data.get("port", 1080),
                    data.get("username", ""),
                    data.get("password", ""),
                )
                self._send_json({"ok": True, "data": res, "msg": f"SOCKS5 连通成功 · 出口 {res['ip']} ({res['country']} {res['city']})"})
            elif path == "/api/socks5/save":
                s5 = save_socks5_routing(data)
                msg = f"家宽 SOCKS5 路由已启用 ({s5['host']}:{s5['port']})" if s5["enabled"] else "已关闭家宽 SOCKS5 路由，恢复 VPS 直出"
                self._send_json({"ok": True, "data": s5, "msg": msg})
            elif path == "/api/restart-xray":
                code, _, err = run_cmd(["systemctl", "restart", "xray"])
                if code != 0:
                    raise RuntimeError(err)
                self._send_json({"ok": True, "msg": "Xray 服务已重启"})
            elif path == "/api/xray/switch-version":
                res = switch_xray_version(data.get("version", ""))
                self._send_json({
                    "ok": True,
                    "data": res,
                    "msg": f"Xray 已从 {res['old_version']} 切换到 {res['new_version']}",
                })
            elif path == "/api/xray/update-geodata":
                update_geodata()
                self._send_json({"ok": True, "msg": "GeoIP / GeoSite 数据已更新并重启 Xray"})
            elif path == "/api/singbox/install":
                ver = install_or_upgrade_singbox()
                self._send_json({"ok": True, "version": ver, "msg": f"sing-box v{ver} 已安装/更新就绪"})
            elif path == "/api/self-check":
                res = self_check_node(data.get("tag", "reality-in"), include_gfw=bool(data.get("gfw", True)))
                self._send_json({"ok": res["ok"], "data": res, "msg": "节点全面体检完成" if res["ok"] else "检测到异常项"})
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
