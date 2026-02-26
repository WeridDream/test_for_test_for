# SEC-001 Threat Model（SoT）
- Doc ID: SEC-001
- Status: FINAL
- Owner: IU
- Last Updated: 2026-02-23
- Depends On: BG-001, FL-001, ARCH-001, PLAN-001, JWT-001, API-001
- Logical Path: docs/04_security/00_threat_model.md
- Revision: r20260223_01
- Supersedes: N/A

---

## 1. 范围与非目标

### 1.1 范围（In Scope）
本威胁模型覆盖认证中台的核心链路与边界：
- 外部入口：Go Gate（`/_auth/gate`, `/_auth/error`）、Envoy（对页面/API 的门禁）
- 内部接口：Rust Issuer、Go Exchange、Go AuthZ、JWKS 内部端点
- 身份与密钥：SPIRE（Workload Identity / mTLS）、SoftHSM2（PKCS#11 签名域）
- 状态存储：Redis（GT/EC 一次性核销映射）、Control Plane（auth_center）
- 典型场景：场景1~4 + webhook（仅 mTLS，不纳入票据体系）

### 1.2 非目标（Out of Scope）
- 不替换业务系统登录/SSO/账号体系
- 不对第三方表单平台做深度改造（除非走 CHG）
- 不讨论跨机房多活、跨地域多云（后续如需另立文档）

---

## 2. 系统概览与安全目标

### 2.1 安全目标（Security Objectives）
- **S1：来源可信**  
  内部调用必须是 mTLS（SPIRE）且 SPIFFE allowlist 命中；外部用户不具备直接调用 Issuer/Exchange/AuthZ 的能力。
- **S2：凭证不可伪造、不可重放**  
  JWT 使用 Ed25519（EdDSA）签名，私钥不出签名域（SoftHSM2）；GrantTicket/EntryCode 一次性核销。
- **S3：身份透传可被下游信任**  
  下游业务只信 Envoy 注入头；入口强制 strip 外部伪造的 `X-Auth-* / X-Biz-* / X-Ctx-*`。
- **S4：最小暴露面**  
  JWKS 仅内部 mTLS 拉取；上游服务不可绕过 Envoy 直连；故障策略明确（受保护路由 fail-closed）。
- **S5：可审计可应急**  
  所有关键决策点必须落审计字段（request_id/trace_id、spiffe_id、client_id、aud、jti、decision、reason）。

---

## 3. 资产、主体与信任边界

### 3.1 关键资产（Assets）
- A1：签名私钥（SoftHSM2 token 内对象、PIN、token 目录）
- A2：有效 JWT（SessionToken/AccessToken）
- A3：GrantTicket / EntryCode（短时一次性票据）
- A4：Control Plane 策略（client/policy/subject_rule/key_metadata/blacklist）
- A5：SPIRE 信任域（trust bundle、SVID、workload entries）
- A6：审计与日志（可用于追责与排障）

### 3.2 主体与攻击者模型（Actors）
- 外部攻击者（Internet）
- 恶意/被攻陷客户端（浏览器/WebView/App）
- 内网横向移动者（攻陷某台业务机/容器后尝试冒充其他服务）
- 供应链风险（依赖/镜像污染）
- 运维误配置（错误路由/错误 allowlist/错误 strip）

### 3.3 信任边界（Trust Boundaries）
- 外部（Untrusted）：Browser/WebView/APP → Envoy/Go Gate（无 mTLS）
- 内部（Trusted Workload）：服务到服务 → 全 mTLS（SPIRE）+ SPIFFE allowlist
- 签名域边界：私钥仅在 Rust Issuer + SoftHSM2 侧，Go 不持有签名私钥
- JWKS 边界：仅内部 mTLS 可访问（仅 Envoy allowlist）

---

## 4. 攻击面清单（Attack Surfaces）
- AS1：`/_auth/gate`（EntryCode 消费 + 302 + Set-Cookie）
- AS2：Envoy 入口（jwt_authn / ext_authz / header strip+inject）
- AS3：内部签发/兑换接口（issue_ticket / exchange_*）
- AS4：JWKS 内部端点
- AS5：Webhook 接收端（仅 mTLS allowlist + 幂等）
- AS6：Redis（一次性票据映射、Lua 核销）
- AS7：SoftHSM2 token 目录与 PIN 管理
- AS8：Control Plane DB（策略误配、越权策略）

---

## 5. 主要威胁与缓解（Threats & Mitigations）

> 表中“缓解”必须能映射到已冻结 SoT（JWT-001/API-001/FL-001/PLAN-001），未落盘视为未完成。

| Threat ID | 威胁描述 | 影响资产 | 典型攻击路径 | 缓解措施（必须） | 观测/审计 |
|---|---|---|---|---|---|
| T-001 | 外部直接调用内部接口（issuer/exchange/authz/jwks） | A1/A4/A5 | 扫描端口/伪造请求 | 内部接口全 mTLS + SPIFFE allowlist；JWKS 仅 allow Envoy | 401/403 计数、caller spiffe_id |
| T-002 | header 伪造绕过身份（外部伪造 `X-Auth-*`） | A2/A6 | 客户端构造同名头 | Envoy 入口 strip `X-Auth-* / X-Biz-* / X-Ctx-*` 再注入 | strip 命中计数、request_id |
| T-003 | EntryCode 重放/双花 | A3/A2 | 并发请求同 entry_code | Redis Lua 原子 GET+DEL；TTL 短；重复返回错误页 | entry_code 使用次数、重复率 |
| T-004 | GrantTicket 重放 | A3/A2 | 多次兑换同 grant_ticket | Redis GETDEL 原子核销；TTL=60s | grant_ticket 重复兑换计数 |
| T-005 | open redirect / target 参数注入 | A2 | `target=http://evil` 或 CRLF | API-001 target 规则：仅相对路径 + allow prefixes + 禁止 scheme/换行 | target 校验失败日志 |
| T-006 | JWT 伪造（签名绕过） | A2/A1 | 获取私钥/绕过验签 | Ed25519；私钥不落库不出 HSM；Envoy jwt_authn 本地验签；JWKS 内部 mTLS | jwt_authn fail reason |
| T-007 | 私钥泄露（SoftHSM2 token 目录/PIN 泄露） | A1 | 文件系统泄露/运维误操作 | token 目录权限、最小授权；PIN 不入库不入镜像；Runbook 备份/恢复；审计与轮换 | HSM 操作失败率、轮换记录 |
| T-008 | JWKS 拉取失败导致大面积 401 | A2 | Issuer/JWKS 抖动 | Envoy cache_duration=300s；轮换 GRACE；监控 jwks fetch | jwks fetch error、cache_age |
| T-009 | ext_authz 抖动放大拒绝（fail-closed） | 可用性 | authz 超时/5xx | 超时=100ms；健康检查；受保护路由清单明确；告警 | authz timeout、deny rate |
| T-010 | ctx 过大导致 header/cookie 超限（431/丢 cookie） | A2 | 业务塞超大 ctx | JWT-001：ctx 扁平+2KB+20项；Issuer 入口强校验；白名单注入 | ctx rejected count |
| T-011 | 绕过 Envoy 直连上游服务 | A2 | 直接打 upstream 端口 | 网络/监听约束：只暴露 Envoy；上游仅内网监听；安全组封禁 | 直连探测、端口暴露检查 |
| T-012 | Webhook 伪造/重放 | 业务数据 | 外部伪造回调/重复投递 | webhook 仅 mTLS+SPIFFE allowlist；幂等键（correlation_id+form_key）重复返回200 | caller spiffe_id、idempotency_hit |

---

## 6. 安全控制落点（Controls Mapping）

### 6.1 认证与身份
- SPIRE：Workload Identity（内部 mTLS 统一入口）
- allowlist：SPIFFE ID → client_id（Control Plane）

### 6.2 凭证与会话
- JWT：Ed25519（EdDSA），kid + JWKS 内部端点
- SessionToken：Cookie（HttpOnly + Secure + SameSite=Lax）
- AccessToken：Bearer

### 6.3 一次性票据（防重放）
- GrantTicket：TTL=60s，GETDEL 原子核销
- EntryCode：TTL=60s，Lua GET+DEL 原子核销

### 6.4 授权与资源绑定
- Envoy jwt_authn：本地验签
- ext_authz：授权/资源绑定，受保护路由 fail-closed
- AuthZ 输入载体：只读 Envoy 注入头（X-Auth* / X-Ctx* / X-Biz*）

### 6.5 可观测与审计
- 最小审计字段：request_id/trace_id、client_id、caller_spiffe_id、aud、jti、decision、reason、latency
- 错误呈现策略：页面 302 错误页；API JSON 错误体（含 request_id）

---

## 7. 残余风险与未决项
- OQ-003：黑名单/禁用传播一致性（目标 <10s，机制在 SEC-002/DEP-ENV 与实现细化）
- 兼容性风险：cross-site iframe Cookie 策略不承诺稳定（提供降级路径）

---

## 8. 验收口径（SEC-001）
- 内部接口无 mTLS 或 SPIFFE 不在 allowlist：必须拒绝（401/403）
- 外部伪造 `X-Auth-* / X-Ctx-* / X-Biz-*`：必须被 strip，且不影响授权结果
- 重放：GrantTicket/EntryCode 重放不可通过（重复投递稳定失败/错误页）
- ctx 超限：必须在 Issuer 入口拒绝（4xx），不进入 Envoy 链路
- 可审计：上述关键拒绝均可用 request_id 定位到决策原因（reason）