# ARCH-001 总体目标架构（SoT）
- Doc ID: ARCH-001
- Status: FINAL
- Owner: IU
- Last Updated: 2026-02-22
- Depends On: BG-001, FL-001
- `Revision: r20260223_04`
- `Supersedes: r20260223_03`
---

## 1. 一句话结论（必须）
本项目建设一套以 **Envoy 本地验签（jwt_authn）+ ext_authz 授权** 为入口、以 **SPIRE 提供内部 Workload mTLS 身份** 为基础、由 **Rust（SoftHSM2/PKCS#11）独占签名域** 与 **Go 承担兑换/门禁** 的通用鉴权中台，在不改动各业务账号体系的前提下统一实现门禁与可信身份透传。

---

## 2. 范围与非目标（必须）
### 2.1 In Scope（对齐 BG-001）
- 票据签发/兑换/网关验签/身份透传
- 内部 Workload Identity：SPIRE 提供 mTLS 身份
- 控制面：client/policy/subject 规则/公钥元数据/黑名单 配置化治理
- 覆盖场景：场景1~4 + webhook

### 2.2 Out of Scope（必须写清）
- 不重做业务服务账号体系（仅门禁+身份透传）
- 第三方表单平台默认零侵入（不改其源码）


---

## 3. 基线与约束（必须）
### 3.1 版本基线（冻结口径）
- Go: 1.26.x
- Rust: 1.93.1
- Envoy: 1.36.4
- SPIRE: 1.14.1
- 前端方向：React + TypeScript + Vite + Tailwind

> 引用：全局约定。:contentReference[oaicite:4]{index=4}

### 3.2 SoT 优先级（用于后续冲突裁决）
DDL > Contracts > decisions.md > design/flows > deploy/runbooks

> 引用：全局约定。:contentReference[oaicite:5]{index=5}

---

## 4. 架构视图（必须）
> ARCH-001 不展开“模块清单”，但必须把关键组件职责、边界、数据流在一页内讲清。

### 4.1 组件与职责边界（容器级）
- Edge Gateway：原生 Envoy（jwt_authn 本地验签；必要时 ext_authz）
- Identity：SPIRE Server + Agent（Workload Identity/内部 mTLS）
- Issuer：Rust（签名域/私钥域；内部接口；SoftHSM2/PKCS#11 执行签名）
- Exchange/Gate/AuthZ：Go（兑换、302 gate、ext_authz 授权判断；不持有签名私钥）
- Control Plane：DB + 管理后台（独立前端）
- Cache：Redis（grant_ticket/entry_code 映射与一次性消费；可选黑名单加速）
- Third-party Form Platform：表单平台（查询/填报页面）
- Biz Systems：业务平台、名医推荐等

> 引用：BG-001 组件与职责边界。:contentReference[oaicite:6]{index=6}

### 4.2 信任边界（外部/内部）
- 外部（Untrusted）：浏览器/WebView/PC/APP；不使用 mTLS
- 内部（Trusted Workload）：服务到服务调用；必须 mTLS（SPIRE）+ SPIFFE allowlist
- JWKS：作为内部端点，仅允许 Envoy 拉取
- 私钥边界：签名私钥仅在 Rust Issuer 控制域；SoftHSM2/PKCS#11 执行签名

> 引用：FL-001 全局不变量。:contentReference[oaicite:7]{index=7}

---

## 5. 数据面与控制面（必须）

### 5.1 Control Plane（策略/配置）
Control Plane 由 **独立数据库 schema（auth_center）+ 独立管理后台（Admin UI：React + Vite + Tailwind）**组成，用于配置化治理并避免业务侧硬编码：

- Client：谁能申请票/调用内部接口（绑定 SPIFFE ID / client_id，支持启用/禁用）
- Policy：允许申请的 audience（target_aud）、最大 TTL（max_ttl）、scope 与资源约束（含路由级授权策略）
- Subject Rule：`subject{type,id} -> sub` 的生成规则（模板/前缀/长度/正则），避免业务平台硬编码 sub
- Key Metadata：**仅公钥元数据与状态**（kid/alg/public_key/status/expires_at），用于 JWKS 展示与 Envoy 拉取；不存储任何私钥
- Blacklist：user/jti 等紧急封禁（传播一致性目标见 OQ-003）

策略下发机制采用 **“控制面写入 + 数据面缓存/定时刷新”**。生效延迟目标（禁用 client、黑名单、策略变更）在 PLAN-001/SEC-001 固化并量化。

### 5.2 Data Plane（请求流转）
- issue_ticket（内部 mTLS）→ grant_ticket（一次性）
- exchange_*（内部 mTLS）→ entry_code/access_token
- gate（外部）→ cookie session_token + 302
- Envoy jwt_authn（本地验签）→ header injection
- ext_authz（内部 mTLS）→ allow/deny + header mutations

> 引用：场景1/2 的关键校验点与流转。:contentReference[oaicite:8]{index=8}:contentReference[oaicite:9]{index=9}

---

## 6. 端到端主链路（只列 4 条，必须）
> 这里不重复 FL-001 细表，只抽象成“主链路”，用于指导后续部署/契约。

### 6.1 场景1：表单门禁（FILL/QUERY）
Client -> Issuer -> Exchange -> Gate -> Envoy(jwt_authn+ext_authz) -> Form Platform

### 6.2 场景2：A -> B（API 调用）
Biz A -> Issuer -> Exchange(access_token) -> App/Biz A -> Envoy(B) -> Biz B

### 6.3 场景3：名医服务（无账号体系）
Caller Service -> Issuer -> Exchange(access_token) -> Envoy(Featured) -> Featured Doctor

### 6.4 Webhook（认证聚焦）
Sender(mTLS) -> Envoy(mTLS allowlist) -> Receiver(Receipt+Outbox 既有闭环)

> 引用：Webhook mTLS 口径与幂等键说明。:contentReference[oaicite:10]{index=10}

---

## 7. Audience Registry（必须）
Audience（aud）表示“被访问的资源域/资源服务器”，必须使用全局通用命名（环境无关），并在控制面 policy 中同步约束。

当前预置（可扩展）：
- `form_platform`：第三方表单平台门禁与相关资源
- `biz_b_api`：业务 B 对外 API 资源域
- `featured_doctor_api`：名医推荐服务对外 API 资源域
- `core_business_api`：核心业务系统 API 资源域

新增业务 aud 命名规则：
- 采用 `<system>_<resource>_api`（小写 + 下划线，长度 ≤ 64，环境无关）
- `aud` 表示资源域，不表示调用方；调用方身份由 `client_id/spiffe_id` 表达

---

## 8. 网关策略（必须）
### 8.1 jwt_authn 与 ext_authz 的分工
- jwt_authn：本地验签（高频）
- ext_authz：授权与资源绑定（强制，例如 formKey 与 ctx 绑定）

> 引用：资源绑定/ext_authz 强制口径。:contentReference[oaicite:12]{index=12}

### 8.2 故障策略（fail-closed）
- 受保护路由：ext_authz 故障 fail-closed（拒绝或 503/403，具体在 DEP-ENV 固化）

> 引用：fail-closed 出现在失败矩阵口径。:contentReference[oaicite:13]{index=13}

### 8.3 统一错误页/错误体
网关错误呈现策略：  
- 页面类路由（如 `/s/*`、`/q/*`）：401/403 统一 302 到 `/_auth/error`（HTML），必须包含 `request_id`  
- API 类路由（如 `/api/*`、`/v1/*`）：401/403 返回 JSON 错误体（包含 `request_id`），不做 302  
  
受保护路由 ext_authz 故障策略：**fail-closed**。

> 引用：FL-001 9.2/9.3。:contentReference[oaicite:14]{index=14}

---

## 9. 未决项（引用 Index Open Questions）
- OQ-003：黑名单传播一致性（多 Envoy 节点一致性目标）

> 引用：Index OQ 列表；BG-001 未决项描述。:contentReference[oaicite:16]{index=16}

---

## 10. 验收口径（ARCH-001 级别）
- 组件职责边界无冲突（特别是：Go 不持有私钥；JWKS 内部拉取；内部全 mTLS）
- 4 条主链路与 FL-001 场景1~4 + webhook 一致
- Audience Registry 与 policy/aud 语义一致
- 错误页/错误体策略能映射到 DEP-ENV（后续可落地）

---