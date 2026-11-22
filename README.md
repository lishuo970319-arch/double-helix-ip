# 🌐 IP X-Ray · IP 与网络环境全景体检台

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-0ea5e9.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-10b981.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-8b5cf6.svg)]()

**IP X-Ray（IP 全景体检台）** 是一款零外部前端依赖、支持打包为独立单文件 `.exe` 的全维度 IP 纯净度与本机代理网络诊断工作台。

它将开源终端体检项目（如 `IPQuality`）的多源数据能力与主流可视化检测站的核心图表（矢量地图、三列 BGP 路由拓扑、14 天 C 段热度曲线、多库彩虹色阶尺、Claude 时区/中文环境遥测防封、16 站真实分流矩阵、Cloudflare 满载延迟测速）融合进一套**带白话导读的现代双主题界面**中。

---

## ✨ 核心特性

- **💬 五维白话总诊断（3 秒看懂，拒绝黑话与虚构总分）**
  - 不编造主观扣分，而是直接将多库客观原值翻译成大白话回答 5 个核心问题：**① 真家宽还是机房/骨干网伪装？② 有没有黑历史污点？③ 用 Claude 会不会因时区穿帮封号？④ 国内外代理分流漏没漏真 IP？⑤ 常用流媒体与带宽体验如何？**
  - 内置**全球主流宽带运营商 / 国际一级骨干网 / 云机房身份百科词典**，自动点破常见“假家宽”骨干号段。
- **📊 全套交互式可视化图表（零外部 CDN 依赖，含离线高精度世界底图）**
  - **脉冲矢量世界地图**：内置 Natural Earth 离线陆地轮廓（`land110.txt`），绘制多地理源散点、最大定位偏差距离（`km`）、到 Cloudflare 接入机房的发光航线弧及全球缩略图。
  - **三列 BGP 国际路由拓扑图**：SVG 贝塞尔连线展示 `宣告源 AS → 直接上游占比 → Tier-1 国际一级主干网`，支持按日期切换历史路由快照。
  - **近 14 天 `/24` 网段拥挤热度面积图**：一眼识别同网段 256 个邻居是否被大规模机场滥用。
  - **原版权威标尺矩阵**：`Net.Coffee` 可信度标尺 + `TikTok / 海外社媒 / AI 大模型` 适用场景三环 + `IPPure / Scamalytics / IP2Location / AbuseIPDB / ProxyCheck / ipquery` 6 段彩虹浮标尺。
- **🤖 Claude / AI 专项防封与本地遥测扫描**
  - **三联出口对比卡**：同屏对照 `本机国内直连参照`、`Cloudflare 出口` 与 `Claude.ai 实际出口` 及 Anthropic 实时组件状态。
  - **时区一致性对撞告警**：正面比对 `IP 归属地时区` 与 `本机操作系统时区`（拦截“外区 IP + `Asia/Shanghai` 时区”穿帮隐患）。
  - **本地 6 维中文环境暴露仪**：纯浏览器本地扫描系统时区、语言序列、Canvas 中文字体枚举、`Intl` 格式、UTC+8 偏移并给出逐项降敏建议。
- **🔀 本机真实链路、隐私防漏与流媒体实测**
  - **国内外 16 站真实分流出口表**：并发核验 `Bilibili / IPIP / 字节跳动 / 网易` 与 `Claude / ChatGPT / OpenAI / Sora / Perplexity / Cloudflare / GitLab / Node.js / Coinbase / OKX` 实际分流出口及后量子密钥交换（`X25519MLKEM768`）。
  - **DNS & WebRTC 防漏 + 协议栈指纹**：`EDNS` + `BrowserLeaks` 多节点中国 DNS 暴露告警、4 组国内外 STUN WebRTC 检测、`TLS JA3 / JA4 / Peetprint` 握手指纹及 `Canvas / WebGL / AudioContext` 128-bit 硬件指纹明细。
  - **14 项平台解锁 & 30 库 DNSBL 黑名单墙**：覆盖 `ChatGPT / Claude / Gemini / YouTube Premium / Netflix / Disney+ / TikTok / Prime Video / Reddit / GitHub / Amazon / Temu / Steam / Stripe`，以及支持分类筛选与 Spamhaus PBL 家宽段识别的 30 家黑名单库。
  - **Cloudflare 满载延迟测速（Bufferbloat）**：测试 `100KB→10MB` 下载阶梯、`256KB→2MB` 上传阶梯、丢包率，并并发采样**下载/上传满载延迟**。
- **🎨 现代双主题工作台**
  - 支持 **🌙 深色极客 / ☀️ 浅色护眼** 一键换肤、**📖 一屏全展 / 🎯 分栏聚焦** 双阅读模式，以及 **👁️ 一键全屏 IP 打码**（安全截图分享）。

---

## 🚀 快速开始

### 方式一：Python 直接运行（跨平台 Windows / macOS / Linux）

```bash
git clone https://github.com/lishuo970319-arch/ip-xray.git
cd ip-xray
pip install -r requirements.txt
python app.py
```

启动后将自动在默认浏览器打开本地工作台（默认端口 `18668`，若占用自动顺延；支持 `--port 18666` 与 `--no-browser` 参数）。

### 方式二：打包为免安装 Windows 单文件 `.exe`

在 Windows 下直接双击运行仓库内的 `build_exe.bat`，或执行：

```bash
pip install -r requirements.txt pyinstaller
pyinstaller --noconfirm --clean --onefile --console --name "IP全景体检台" --icon "icon.ico" --add-data "index.html;." --add-data "land110.txt;." --hidden-import socks --hidden-import urllib3.contrib.socks app.py
```

打包完成后，独立的 `dist\IP全景体检台.exe` 可直接发给未安装 Python 的朋友双击即用。

---

## 🔒 隐私说明

- 所有历史检测记录仅保存在本机运行目录下的 `ip_check_history.json`（已默认写入 `.gitignore`），不会上传至任何第三方收集服务器。
- 浏览器指纹与中文环境特征检测均在本地浏览器内存内完成计算。

---

## 🙏 致谢与数据参考

- 多源风控检测思路致敬开源项目 [xykt/IPQuality](https://github.com/xykt/IPQuality)
- 离线世界海岸线矢量数据基于 Public Domain (CC0) 的 [Natural Earth 1:110m](https://www.naturalearthdata.com/)
- 各风险、路由与测速指标均实时取自对应公开网络服务接口原值

## 📄 License

本项目基于 [MIT License](./LICENSE) 开源。
