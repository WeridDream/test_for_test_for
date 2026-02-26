# SEC-002 Identity & mTLS with SPIRE（SoT）
- Doc ID: SEC-002
- Status: FINAL
- Owner: IU
- Last Updated: 2026-02-25
- Depends On: ARCH-001, PLAN-001, JWT-001, API-001, DDL-001
- Logical Path: docs/04_security/01_identity_mtls_spire.md
- Revision: r20260223_02
- Supersedes:  r20260223_01

---

## 1. 目标与范围

### 1.1 目标
- 将“内部调用可信”从 IP/网络拓扑升级为 **Workload Identity**：内部接口统一使用 **mTLS（SPIRE X.509-SVID）+ SPIFFE allowlist**。
- 明确：哪些接口属于“内部接口”（必须 mTLS），哪些属于“外部接口”（不使用 mTLS）。
- 给出非 k8s 环境下 SPIRE 的部署、注册、轮换与最小运维约束，使其可落地、可回归、可审计。

### 1.2 范围
覆盖以下参与方的身份与 mTLS：
- Envoy Gateway（边缘网关）
- Rust Issuer（签名域）
- Go Exchange / Go Gate / Go AuthZ
- 业务平台/调用方（如 jeecg-boot、biz-a 等）
- 表单平台（纳入 SPIRE，用于 webhook）

不覆盖：业务系统自身账号体系（不做 SSO/登录）。

---

## 2. 信任边界与接口分层（硬约束）

### 2.1 外部接口（Untrusted，不走 mTLS）
- `GET /_auth/gate`（浏览器/WebView 入口）
- `GET /_auth/error`（统一错误页）

外部接口不做 mTLS；可信性由 **一次性 EntryCode + Cookie(HttpOnly)** 与 Envoy 的 jwt_authn/ext_authz 保障（见 FL-001/JWT-001/API-001）。

### 2.1.1 资源域网关路由策略（A：protect-by-default）
- 在资源域网关（Envoy）上：除 `/_auth/*` 外，其余路由一律视为“受保护路由”，必须通过 jwt_authn（Cookie/Bearer）与 ext_authz（授权/资源绑定）。
- 该路由策略的具体配置以 DEP-ENV-001 为准；SEC-002 仅声明其为“身份与信任边界”的硬约束。

### 2.2 内部接口（Trusted Workload，全部必须 mTLS）
以下接口一律要求：
- 客户端必须持有 SPIRE X.509-SVID
- 服务端必须校验 mTLS，并从对端证书的 URI SAN 提取 SPIFFE ID
- SPIFFE ID 必须命中 allowlist（Control Plane：`sys_auth_client_identity`）

内部接口清单：
- Rust Issuer：`POST /v1/internal/issue_ticket`
- Rust Issuer：`GET /.well-known/jwks.json`（仅 Envoy allow）
- Go Exchange：`POST /v1/exchange/entry_code`
- Go Exchange：`POST /v1/exchange/access_token`
- Go AuthZ：`POST /ext_authz/check`（仅 Envoy allow）
- Webhook：`POST /api/webhook/data`（仅 form_platform allow）

---

## 3. 身份命名规范（SPIFFE ID Scheme）

### 3.1 Trust Domain
- `trust_domain`：建议固定为公司/平台域名（示例：`xjiot.link`）
- 全局唯一，不包含环境或机房信息（环境隔离通过 ns 体现）。

### 3.2 SPIFFE ID 规范
推荐格式（稳定、可读、可映射到 client_id）：
- `spiffe://<trust_domain>/ns/<env>/sa/<service_name>`

字段约束：
- `<env>`：`prod | preprod | dev`（按你们环境实际取值）
- `<service_name>`：小写+中划线（如 `envoy-gateway`, `rust-issuer`, `go-exchange`, `go-authz`, `form-platform`, `jeecg-boot`, `biz-a`）

示例：
- `spiffe://xjiot.link/ns/prod/sa/envoy-gateway`
- `spiffe://xjiot.link/ns/prod/sa/rust-issuer`
- `spiffe://xjiot.link/ns/prod/sa/go-exchange`
- `spiffe://xjiot.link/ns/prod/sa/go-authz`
- `spiffe://xjiot.link/ns/prod/sa/form-platform`
- `spiffe://xjiot.link/ns/prod/sa/jeecg-boot`
- `spiffe://xjiot.link/ns/prod/sa/biz-a`

---

## 4. SPIRE 部署拓扑（非 k8s）

### 4.1 SPIRE Server
- 单实例（可先单点，后续按运维成熟度再扩 HA）
- 对外暴露 gRPC 端口（示例：`8081/tcp`），仅供 Agent 主动连接
- 负责 CA、签发 SVID、维护 trust bundle

### 4.2 SPIRE Agent（每台机器一份）
- 每台需要参与 mTLS 的机器都部署 Agent
- Agent 通过出站连接 SPIRE Server 获取信任与更新
- Workload 通过 **本机 Unix Domain Socket** 与 Agent 交互获取 SVID：
  - 默认建议：`/tmp/spire-agent/public/api.sock`

### 4.3 Envoy 与 SPIRE 的关系
- Envoy 自身作为 Workload：从本机 Agent 获取 SVID（用于调用 AuthZ/JWKS 的 mTLS）
- Envoy 在“对内”发起调用（/ext_authz/check、/jwks）时必须使用 mTLS（SPIRE SVID）
- Envoy 在“对外”承接浏览器流量时不使用 mTLS（TLS/HTTPS 可单独配置）

---

## 5. Workload 注册与 allowlist 映射（关键闭环）

### 5.1 注册（SPIRE Entries）
在 SPIRE Server 中为每个 workload 注册 entry，至少包含：
- `spiffe_id`：按第 3 章规范
- `parent_id`：该机器对应的 agent SPIFFE ID
- `selectors`：用于证明该进程/容器就是该 workload（非 k8s 推荐 unix attestor）

非 k8s 推荐 selector 组合（避免“同 uid 冒充”）：
- `unix:uid:<uid>`（必选）
- `unix:path:<absolute_binary_path>`（推荐）
- （可选）`unix:gid:<gid>`

> 原则：**每个服务使用专用 Unix 用户**运行，做到“uid 即身份边界”。

### 5.2 allowlist（Control Plane）
- `auth_center.sys_auth_client_identity.spiffe_id` 存储上面的 `spiffe_id`
- 运行时校验：
  - 服务端在 mTLS 握手后提取对端 SPIFFE ID
  - 到本地缓存/DB 查询 allowlist：
    - 允许：进入业务处理
    - 不允许：403

### 5.3 内部接口调用权限矩阵（最小集）
| 内部接口 | 允许调用者（client_id / spiffe_id） |
|---|---|
| `POST /v1/internal/issue_ticket` | jeecg-boot、biz-a、其它受信业务后端 |
| `POST /v1/exchange/*` | jeecg-boot、biz-a、其它受信业务后端 |
| `POST /ext_authz/check` | envoy-gateway（仅 Envoy） |
| `GET /.well-known/jwks.json` | envoy-gateway（仅 Envoy） |
| `POST /api/webhook/data` | form-platform（仅表单平台回调方） |

> 说明：上述“允许集合”由 Control Plane 配置化治理，不在代码中写死。

---

## 6. mTLS 行为规范（客户端/服务端）

### 6.1 服务端（Rust Issuer / Go Exchange / Go AuthZ / Webhook Receiver）
必须实现：
1) 启用 mTLS，要求对端提供证书（ClientAuth=RequireAndVerify）
2) 校验证书链（SPIRE trust bundle）
3) 解析对端证书 URI SAN 得到 SPIFFE ID
4) allowlist 校验（spiffe_id -> client_id）
5) 记录审计字段：`caller_spiffe_id`、`client_id`（若可映射）、`request_id`

禁止行为：
- 仅靠 IP 白名单放行内部接口
- 信任来自请求头的“身份”字段（身份只来自 mTLS）

### 6.2 客户端（业务平台 / Envoy / 表单平台）
必须实现：
1) 从本机 SPIRE Agent 获取 SVID（动态轮换）
2) 发起 mTLS 请求到内部接口
3) 对端证书校验：必须校验 SPIRE trust bundle（防中间人）

---

## 7. 轮换与可用性（SVID Rotation）

### 7.1 轮换机制
- SVID 有有限 TTL（由 SPIRE 控制），Workload 必须能自动续期
- 建议使用：
  - SPIFFE Workload API SDK（应用层自动 reload）
  - 或 Envoy SDS（Envoy 自动 reload）

### 7.2 故障预期
- Agent 不可用 → Workload 无法获取/续期 SVID → 内部调用失败（应快速暴露并告警）
- Server 不可用但已有 SVID/缓存：
  - 在 TTL 窗口内通常仍可继续工作
  - 超过 TTL 后会失败
- 处理策略：
  - 将 SPIRE Server/Agent 纳入“高优先级基础设施告警”
  - 保留 Runbook：重启、证书/信任包修复、健康检查

---

## 8. 本机 Socket 安全（必须）

### 8.1 `/tmp/spire-agent/public/api.sock` 权限
- 该 socket 必须仅对需要的服务用户/组可读写
- 禁止将该 socket 以过宽权限暴露给任意用户（否则同机恶意进程可冒用身份）

### 8.2 服务用户隔离
- 每个服务一个 Unix 用户（推荐）
- SPIRE entry selectors 用 `uid + path` 组合绑定，降低“同机冒充”风险

---

## 9. 可观测与审计（最小集）

### 9.1 必记字段
- `request_id` / `trace_id`
- `caller_spiffe_id`
- `client_id`（若可映射）
- `target_aud`（issue_ticket/exchange）
- `decision`（allow/deny）
- `reason`（deny 的具体原因）
- `latency_ms`

### 9.2 关键告警（建议）
- SPIRE Agent 与 Server 连接异常
- SVID 获取失败率、续期失败率
- mTLS 握手失败率
- allowlist deny 突增

---

## 10. 验收口径（SEC-002）
- 任意内部接口：
  - 无证书/证书无效：必须拒绝（401）
  - SPIFFE ID 不在 allowlist：必须拒绝（403）
- Envoy 访问 AuthZ/JWKS：
  - 必须走 mTLS 且 SPIFFE allowlist 命中
- Webhook：
  - 非 form-platform 身份不得进入业务接收端
- 轮换：
  - Workload 不重启也能完成证书轮换（或在 TTL 内稳定续期）