# NodeHub

> **A Git-bootstrapped command mesh for autonomous agent fleets — workers hold zero push credentials.**
>
> 节点自举组网协议：命令走只读通道下发，节点零凭证接入，身份+安全双重门禁。

[English](#english) | [中文](#中文)

---

## English

Fleets of autonomous compute nodes (GPU boxes, cloud instances, edge machines) usually die in one of two ways: **credential sprawl** (every worker needs push access somewhere) or **unchecked remote execution** (someone can pipe `curl | sh` into your nodes).

NodeHub — distilled from the ZONGYUAN-ROOT node mesh (protocol `NTFY-CONNECT-001`) — solves both:

| Property | Mechanism |
|---|---|
| **Zero-credential workers** | Commands flow through a read-only channel (public Git "command slot" repo or pub/sub topic); workers only ever PULL. Results/heartbeats go back over an authenticated report endpoint, token injected via environment |
| **Identity gate** | Every inbound message carries `{proto, zr_did}`; mismatches are dropped before parsing |
| **Safety gate** | Default-deny command filter: dangerous-pattern blacklist + allowed-prefix whitelist, case-insensitive, applied before any shell runs |
| **Idempotent execution** | `task_id` done-ledger persisted to disk — restarts never replay commands |
| **Content-pinned boot** | `BaselineVerifier`: a node earns its capability level only if kernel assets hash-match an official baseline; missing → `LOCKED`, mismatch → suspected tampering |
| **Graceful ops** | Exponential backoff 5→60s capped, heartbeat batching, pluggable transport |

### 60-second tour

```python
from nodehub import CommandBus, SlotWorker, BaselineVerifier

# 1. A worker node — transport is injectable (git pull / ntfy / HTTP poll)
bus = CommandBus("ZR-NODE-01",
                 fetch=lambda: git_slot_pull(),      # read-only channel
                 publish=lambda m: report_endpoint_post(m))
worker = SlotWorker(bus, done_file=".zr/done.json")
worker.run_forever(interval=30)      # poll → safety-gate → execute → report

# 2. A controller — broadcast or target a node
bus2 = CommandBus("controller", fetch=list, publish=send)
bus2.poll()

# 3. Boot-time baseline pinning
v = BaselineVerifier("BASELINE-V41", "Lv10",
                     fetch_official=lambda: pull_manifest_from_gateway())
verdict = v.verify("./kernel_assets", critical_assets)
assert verdict["exit_code"] == 0, verdict   # else stay LOCKED
```

Requirements: Python 3.10+, **zero dependencies**.

### Threat model summary

| Attack | Defense |
|---|---|
| Forged command on the channel | `zr_did` + proto identity check → dropped |
| `curl … \| sh` / destructive commands | blacklist + default-deny prefix whitelist |
| Node replay after crash | persistent `task_id` done-ledger |
| Tampered kernel assets | baseline SHA256 pinning → level lockdown |
| Stolen worker credentials | workers hold none — read-only pull only |

---

## 中文

自治算力节点群（GPU 实例、云主机、边缘机）通常死于两种方式：**凭证蔓延**（每个 worker 都要 push 权限）或**未校验的远程执行**（任何人都能 `curl | sh` 进你的节点）。

NodeHub 提炼自 ZONGYUAN-ROOT 节点组网协议（`NTFY-CONNECT-001`），同时解决两者：

| 特性 | 机制 |
|---|---|
| **节点零凭证** | 命令经只读通道下发（公开 Git 命令槽仓库或订阅主题），worker 只拉不推；结果/心跳经鉴权上报端点回传，令牌仅环境变量注入 |
| **身份门禁** | 每条入站消息携带 `{proto, zr_did}`，不匹配直接丢弃 |
| **安全门禁** | 默认拒绝的命令过滤器：危险模式黑名单 + 允许前缀白名单，大小写不敏感，shell 执行前强制过检 |
| **幂等执行** | `task_id` done 台账落盘持久化——重启不重放 |
| **内容钉扎启动** | `BaselineVerifier`：内核资产哈希与官方基线一致才授予能力等级；缺失 → `LOCKED`，不匹配 → 疑似篡改 |
| **稳健运维** | 指数退避 5→60s 封顶、心跳批量、传输层可插拔 |

### 威胁模型速览

| 攻击 | 防御 |
|---|---|
| 通道伪造命令 | `zr_did` + 协议身份校验 → 丢弃 |
| `curl … \| sh` / 破坏性命令 | 黑名单 + 默认拒绝前缀白名单 |
| 节点崩溃后重放 | 持久化 `task_id` done 台账 |
| 内核资产被篡改 | 基线 SHA256 钉扎 → 等级锁定 |
| worker 凭证泄露 | worker 无凭证——只读拉取 |

### 快速上手

```python
from nodehub import CommandBus, SlotWorker, BaselineVerifier

bus = CommandBus("ZR-NODE-01", fetch=git_slot_pull, publish=report_endpoint_post)
SlotWorker(bus, done_file=".zr/done.json").run_forever(interval=30)

v = BaselineVerifier("BASELINE-V41", "Lv10", fetch_official=pull_manifest)
verdict = v.verify("./kernel_assets", critical_assets)
```

依赖：Python 3.10+，**零第三方依赖**。

---

## 来源与治理

- 本仓库从 [ZONGYUAN-ROOT](https://atomgit.com/zongyuangen/ZONGYUAN-ROOT)（branch `converge-20260928`）提炼：`07_代码与脚本/zr_node_protocol.py` · `zr_node_git.py` · `verify_node_baseline.py` · `zr_bootstrap.sh`
- 遵循「元极恒一」治理规范：基准资产只读、衍生独立建库；上游硬编码的节点名/私有路径/凭证文件回退已全部移除，改为环境变量与注入点
- 许可：Apache-2.0
