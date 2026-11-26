# QuackUI

> Lightweight, Local-First Xray Management Panel by **FanDuck**  
> 轻量、本地优先、零第三方依赖的 Xray 节点可视化面板

## Why QuackUI? / 为什么选择 QuackUI？

- **Local-First Security / 本地优先安全**：默认仅监听 `127.0.0.1:8088`，通过 SSH 本地隧道访问，**绝不向公网暴露管理端口**。
- **Zero Python Dependencies / 零第三方依赖**：纯 Python 3 标准库 + 内置 SQLite3，内存占用极低（< 25 MB），代码透明易审计。
- **Anti-Censorship Toolkit / 防封特色工具**：
  - 一键轮换 IPv6 `/64` 入站地址（自动探测网卡前缀并持久化）
  - 修改 Reality 伪装域名（SNI）前自动检测 TLS 1.3 + HTTP/2
  - **五维节点体检 & GFW 阻断检测**：并行检测中国大陆多点 TCP 端口连通性（基于 Globalping 开源探针）、Reality 延迟、实际出口 IP、伪装 SNI 健康度与国内分流拦截状态
  - **Xray 内核版本管理**：内置拉取 GitHub 官方历史版本列表，支持一键升级或任意历史版本降级回退（切换前自动备份旧二进制，配置校验失败自动回滚）与 GeoIP/GeoSite 一键更新
- **Full Persistence & Multi-Node / 流量持久化与多节点管理**：
  - SQLite 持久化记录今日 / 本月 / 近 14 天历史流量，重启不丢数据
  - **Xray + sing-box 双内核引擎**：支持网页端一键模板或自由组合 `VLESS + XHTTP + Reality`、`VLESS + Vision + Reality`、`AnyTLS`、`Hysteria 2`（自动联动 `nftables` UDP 端口跳跃）、`TUIC v5`、`VMess`、`Trojan`、`Shadowsocks-2022`，新建/删除节点自动放行与回收防火墙端口
  - 支持一键复制 VLESS 链接、Clash / Mihomo YAML 片段、离线 SVG 二维码
  - 可视化路由与出站策略开关（拦截国内流量、屏蔽 BT、仅 IPv4 出站）
  - **家宽 SOCKS5 一键出口路由**：支持快捷粘贴解析 `ip:port:user:pass` / `socks5://`、实时测试家宽落地 IP 与运营商，支持全局 / AI 与流媒体 / 自定义域名三种出口分流模式
  - 一键打包下载 `.tar.gz` 完整配置备份，支持中英文切换与深浅色主题

## Quick Start / 快速安装

```bash
git clone https://github.com/FanDuck/QuackUI.git
cd QuackUI
sudo bash install.sh
```

Then open an SSH tunnel from your local computer:

```bash
ssh -N -L 8088:127.0.0.1:8088 root@YOUR_SERVER_IP
```

Open **`http://127.0.0.1:8088`** in your browser.

## Project Structure / 目录结构

```text
/opt/quackui/
├── app.py          # Pure Python 3 backend + SQLite3 traffic collector
├── web/
│   ├── login.html  # Login page (ZH/EN)
│   └── index.html  # Dashboard, multi-node manager, routing, logs, backup
├── install.sh      # One-click installer for Debian/Ubuntu
├── README.md
└── .gitignore      # Ignores config.json & quackui.db
```

## License

MIT License © FanDuck

