# FL-001 端到端流程（SoT）
- Doc ID: FL-001  
- Status: FINAL  
- Owner: IU  
- Last Updated: 2026-02-25
- Depends On: BG-001
- Revision: r20260223_03
- Supersedes: r20260223_02
---
## 1. 文本目标
- 将BG-001的场景1~4 + webhook 写成可落地的端到端时序/状态流转
- 明确每一步的"参与方/请求/凭证/校验点/存储写入/失败表现/审计点"
- 输出可验收口径（可测、可观察、可回归）
---
## 2. 全局不变量（必须）

### 2.1 信任边界与接口分层

- 外部（Untrusted）：浏览器/WebView/PC/APP 发起的请求；不使用 mTLS。
  - 外部入口示例：`GET /_auth/gate?...`、`GET /s/*`、`GET /q/*`、业务 API 入口（Bearer/Cookie）。
- 内部（Trusted Workload）：服务到服务调用；**全部必须 mTLS（SPIRE）+ SPIFFE allowlist**（P1-B）。
  - 内部接口示例：
    - Client -> Rust Issuer：`POST /v1/internal/issue_ticket`
    - Client -> Go Exchange：`POST /v1/exchange/entry_code`（以及未来的 access_token 兑换）
    - Envoy -> Go AuthZ：`POST /ext_authz/check`
    - Envoy -> JWKS Provider：`GET /.well-known/jwks.json`（仅允许 Envoy 拉取）
- 私钥边界：签名私钥仅在 Rust Issuer 控制域；**采用 SoftHSM2/PKCS#11 执行签名**；
### 2.2 统一凭证语义（类型 / TTL / 一次性）

- GrantTicket：内部短票（一次性），用于“签发域 -> 兑换域”的短链路搬运。
  - TTL 默认：60s（建议范围 30~300s）
  - 一次性：必须原子核销（GETDEL 或 Lua GET+DEL）
- EntryCode：外部敲门码（一次性），用于浏览器/WebView 进入 gate 完成种 Cookie。
  - TTL 默认：60s（建议范围 30~120s）
  - 一次性：必须 Lua 原子核销，防并发双花/重放
- SessionToken：Cookie 中 JWT（HttpOnly），用于页面后续请求自动携带。
  - TTL 默认：20min（建议范围 10~30min）
  - 载体：`Set-Cookie: session_token=<JWT>; HttpOnly; Secure; SameSite=Lax; Path=/`
- AccessToken：Bearer JWT，用于 API/服务间调用（APP/PC 调业务 API）。
  - TTL 默认：15min（建议范围 5~30min）
  - 载体：`Authorization: Bearer <JWT>`

统一字段（所有 JWT）：`iss, sub, aud, jti, iat, exp` + `ctx`（ctx 约束在 JWT-001 定型；当前要求 ctx 为扁平键值对，禁止嵌套对象/数组）。

### 2.3 网关注入与下游信任规则（Header Injection）

- Envoy 负责：
  - `jwt_authn` 本地验签（Cookie/Bearer）
  - 通过 Lua 或 ext_authz 将 claims/ctx 清洗为下游可消费的 Header（实现方式在 DEP-ENV/JWT-001 定型）

- 下游服务信任规则（必须）：
  - 下游**只信任 Envoy 注入的身份头**，不得信任客户端直接传入的同名 Header。
  - Envoy 在入口必须 **strip** 掉所有外部请求中已有的 `X-Auth-*`、`X-Biz-*`、`X-Ctx-*`，再由 Envoy 重新注入（防伪造）。

- Header 规范（全局统一）：
  - `X-Auth-Subject: <sub>`
  - `X-Auth-Audience: <aud>`
  - `X-Auth-Scopes: <space-separated scopes>`（如无可省略）
  - `X-Biz-Form-Key / X-Biz-Correlation-Id / X-Biz-Allowed-Serial`（表单场景常用）
  - `X-Ctx-<Kebab-Case-Key>: <value>`（ctx 扁平化透传：默认“白名单透传”，白名单规则在 JWT-001/Policy 定型）
### 2.4 Audience Registry（aud命名约定）
- `aud` 表示“被访问的资源域/资源服务器”，必须使用全局通用命名，不携带环境/域名/IP/端口信息。  
- 命名规则：小写 + 下划线，长度 ≤ 64：`[a-z][a-z0-9_]{1,63}`。  
- `aud` 的取值必须来自本项目 SoT 的 Audience Registry（可在控制面 policy 中同步约束）。  
  

当前预置（可扩展）：  
- `form_platform`：第三方表单平台门禁与相关资源  
- `biz_b_api`：业务 B 对外 API 资源域  
- `featured_doctor_api`：名医推荐服务对外 API 资源域
- `core_business_api`：核心业务系统API

### 2.5 网关-服务最小契约（最小冻结；YAML 后置）

> 目的：在不冻结 envoy.yaml 的前提下，冻结“组件间接口语义”，保证 Rust Issuer / Go Gate(Exchange) 的实现不因后续 Envoy 配置细节返工。
> 非目标：不在本节确认具体 Envoy route/cluster/SDS/Lua 配置细节。

#### 2.5.1 凭证承载与命名（必须）
- WebView/Iframe/浏览器会话凭证：使用 Cookie 传递
  - Cookie Name：`session_token`（固定）
  - Cookie 属性：`HttpOnly=true`、`Secure=true`（生产）、`SameSite=Lax`、`Path=/`
- App / M2M 请求凭证：使用 Header 传递
  - Header：`Authorization: Bearer <JWT>`

#### 2.5.2 固定入口与端点（必须）
- Go Gate（外部放行入口，不要求 JWT）
  - `GET /_auth/gate?entry_code=...&target=...`
  - 行为：核销 `entry_code`（一次性）→ `Set-Cookie(session_token=<JWT>)` → `302` 跳转到 `target`
- Rust Issuer（内部 mTLS + SPIFFE allowlist）
  - `POST /v1/internal/issue_ticket`：签发 GrantTicket（内部短票，写 Redis）
  - `GET /.well-known/jwks.json`：输出 JWKS（仅内部 mTLS，且仅允许 Envoy 工作负载拉取）
- Go Exchange（内部调用）
  - `POST /v1/exchange/entry_code`：GrantTicket → EntryCode（一次性短码）

#### 2.5.3 JWT 基本语义（必须）
- `iss`：固定为 `xjiot-auth-center`（或你们已在 SoT 固定的同值）
- `aud`：资源域（例如 `form_platform` / `biz_b_api` / `featured_doctor_api` / `core_business_api`）
- `sub`：由 `sys_auth_subject_rule` 规则生成（仅 `user` / `service`）
- `scopes`：空格分隔字符串；由 `sys_auth_policy.allowed_scopes` 限制
- `ctx`：业务上下文键值对；必须满足 JWT-001 的约束（总大小/键名/值长/条目数）并受 `ctx_key_allowlist_json` 限制

#### 2.5.4 可信身份透传（必须）
- 网关（Envoy）必须对外部请求执行：
  1) **不信任外部同名头**：任何 `X-Auth-*`、`X-Ctx-*`（以及你们约定的业务头前缀）都必须先 strip
  2) **验签通过后注入可信头**（下游业务只能读这些头，不读 URL/前端 userId）：
     - `X-Auth-Subject: <sub>`
     - `X-Auth-Audience: <aud>`
     - `X-Auth-Scopes: <scopes>`（可空）
     - `X-Auth-JTI: <jti>`
     - `X-Ctx-<Key>: <Value>`（ctx 扁平化；Key 的大小写/下划线转连字符规则以部署文档为准）

#### 2.5.5 错误与失败口径（必须）
- 受保护路由（除 `/_auth/*` 外）：
  - 缺失/无效 JWT：返回 `401`（或 `403`，以网关策略统一为准），**fail-closed**
- `/_auth/gate`：
  - entry_code 缺失/过期/已使用：跳转到统一错误页（或返回 4xx），语义为“链接已失效”

#### 2.5.6 禁止事项（必须）
- 禁止：每个业务请求都远程调用 Rust/Go 进行 verify（Issuance/Verification 必须分层）
- 禁止：业务服务从前端参数直接信任 userId/correlationId（必须以 Envoy 注入头为准）

---
## 3. 场景1：第三方表单门禁（填报/查询）（必须）

### 3.1 目标
- 未授权用户无法访问第三方表单平台在该 `aud=form_platform` 域上的任何路径（**除 `/_auth/\*` 外一律受保护**）；授权用户完成 gate 后，后续资源请求依赖 `SessionToken` 自动携带并持续通过。

- 授权用户通过一次性 `EntryCode` 完成“敲门”后，后续页面资源请求依赖 `SessionToken`（HttpOnly Cookie）自动携带并持续通过。
- 业务上下文（`form_key`、`correlation_id`、`allowed_serial` 等）全链路不可被前端篡改；下游只信任 Envoy 注入 Header。

### 3.2 参与方
- Client（受托业务平台）：JeecgBoot/业务A（具备 SPIFFE 身份）
- Rust Issuer：签名/签发域（内部 mTLS），**使用 SoftHSM2 执行签名**
- Go Exchange：兑换域（内部 mTLS）
- Go Gate：外部门禁入口（外部接口）
- Redis：短票映射与一次性核销
- Envoy：入口网关（本地 `jwt_authn`；`ext_authz` 做资源绑定）
- Third-party Form Platform：第三方表单平台（被保护上游）

### 3.3 前置条件（引用全局不变量）
- 内部接口全部 mTLS + SPIFFE allowlist（见 2.1）
- 凭证语义与 TTL（见 2.2）：
  - GrantTicket=60s（一次性）
  - EntryCode=60s（一次性）
  - SessionToken=20min（Cookie，SameSite=Lax）
- Envoy strip 并重新注入 `X-Auth-* / X-Biz-* / X-Ctx-*`（见 2.3）
- JWKS 端点为内部接口，仅允许 Envoy 拉取（见 2.1）

### 3.3.1 路由保护策略（A：protect-by-default）

- Envoy（form_platform 网关）仅放行公共路由：
  - `/_auth/*`（Go Gate/错误页，不做 jwt_authn / ext_authz）
- 除上述公共路由外，**所有路径默认受保护**：
  - 必须携带 `SessionToken`（Cookie）或 `AccessToken`（Bearer）
  - Envoy 执行本地 jwt_authn；再走 ext_authz 做资源绑定/授权
- 目的：避免第三方表单平台新增/调整资源路径导致“漏保护”。



### 3.4 端到端步骤表（Step Table）
> 说明：填报与查询共享同一条“签发→兑换→敲门→验签→放行”主链路；差异体现在 ctx 内容与资源绑定规则。

| Step | Caller -> Callee | Interface | Authn | Input (摘要) | Output (摘要) | Store（建议） | OnFail | Audit |
|---:|---|---|---|---|---|---|---|---|
| 1 | Client -> Rust Issuer | `POST /v1/internal/issue_ticket` | mTLS(SPIRE) | `subject{type,id}`, `target_aud=form_platform`, `ctx{form_key, correlation_id, action, allowed_serial?}` | `grant_ticket`, `expires_in=60` | Redis `gt:{grant_id}` = SignedJWT（TTL=60s） | 401/403/500 | trace_id, client_id, spiffe_id, target_aud, decision |
| 2 | Client -> Go Exchange | `POST /v1/exchange/entry_code` | mTLS(SPIRE) | `grant_ticket` | `entry_code`, `gate_url` | 原子核销 `GETDEL gt:{grant_id}`；写 `ec:{entry_id}` = SignedJWT（TTL=60s） | 403/500 | entry_id, jti, decision |
| 3 | Browser/WebView -> Go Gate | `GET /_auth/gate?entry_code=...&target=...` | None（外部） | `entry_code`, `target` | `Set-Cookie(session_token=JWT)` + `302 target` | Lua 原子核销：`GET ec:{entry_id}` + `DEL`（一次性） | 302 错误页 / 403 / 400 | entry_id, client_ip, ua, decision |
| 4 | Browser/WebView -> Envoy | `/s/{formKey}...` 或 `/q/{formKey}...` | Cookie(JWT) | Cookie `session_token` | allow/deny | Envoy 本地验签（无存储） | 401（无token/无效/过期） | Envoy access log + jwt_authn 指标 |
| 5 | Envoy -> Go AuthZ | `POST /ext_authz/check` | mTLS(SPIRE) | path/method + claims(sub/aud/ctx) | allow/deny + header mutations | （可选缓存后续定） | 403 / 5xx（按策略处理） | decision, reason, binding_result |
| 6 | Envoy -> Form Platform | upstream route | （可选 mTLS） | 注入 Header（X-Auth-* / X-Biz-*） | 页面/资源响应 | 无 | 5xx | upstream status/latency |

### 3.5 ctx 内容与 action 约定（场景1）
- 填报（FILL）：
  - `ctx.action = "FILL"`
  - 必须：`ctx.form_key`, `ctx.correlation_id`
- 查询（QUERY）：
  - `ctx.action = "QUERY"`
  - 必须：`ctx.form_key`, `ctx.correlation_id`
  - 若需要限定查询范围：必须包含 `ctx.allowed_serial`

原则：URL 上的 query（如 correlationId/serialNumber）不可信；只认 token ctx 与 Envoy 注入 Header。

### 3.6 关键校验点（必须）
1) **Client 身份校验（mTLS + allowlist）**
- Rust Issuer、Go Exchange、Go AuthZ 只接受登记过的 `spiffe_id -> client_id` 调用。

2) **策略校验（control plane policy）**
- Rust Issuer 必须校验：`client_id` 是否允许 `target_aud=form_platform`，TTL 是否不超过 max_ttl。
- subject 生成规则：结构化 `subject{type,id}` 必须满足该 client 的 subject rule（模板/前缀/正则/长度）。

3) **一次性消费（防重放）**
- GrantTicket：必须原子核销（GETDEL 或 Lua），禁止重复兑换。
- EntryCode：必须 Lua 原子核销（GET+DEL），防并发双花与重放。

4) **Envoy 本地验签（高频）**
- `jwt_authn` 校验：签名、iss、aud、exp/iat、kid 对应 JWKS。
- Cookie 固定：`session_token`（禁止 token 出现在 URL）。

5) **资源绑定（ext_authz 强制）**
- `{formKey}` 必须等于 `ctx.form_key`，不一致直接 deny。
- 查询场景：若存在 `ctx.allowed_serial`，则必须与查询请求携带的 serial/参数一致，否则 deny。

### 3.7 失败表现（统一口径）
- `grant_ticket` 无效/过期/重复：Go Exchange 返回 403（内部）；记录审计。
- `entry_code` 无效/已用：Go Gate 返回 302 到错误页（用户友好）或 403（API 模式）。
- Cookie 缺失/验签失败：Envoy 返回 401（可配置跳转错误页）。
- 资源绑定失败：403（可配置错误页）。

### 3.8 最小审计字段（建议）
- trace_id/request_id
- client_id、caller spiffe_id（内部调用）
- subject(type/id) 与最终 sub
- target_aud、action（FILL/QUERY）
- jti、iat/exp
- decision/reason（policy deny / expired / replay / binding fail）
- Envoy 与上游延迟、状态码

### 3.9 可回归验收用例
1) 正常填报：拿到 gate_url → 进入表单填报页成功；后续资源请求持续带 cookie。
2) 重放：同一 gate_url 第二次打开失败（错误页/403）。
3) 篡改 formKey：把 target 或路径里的 formKey 改掉，访问被拒（403 或 401）。
4) 无票访问：直接访问 `/s/*` `/q/*` 返回 401。
5) 禁用 client：禁用后内部 issue/exchange 请求失败（生效延迟目标在 NFR/PLAN 定型）。
---
## 4. 场景2：业务A 融合业务B（A->B）（必须）

### 4.1 目标
- A 的 App 用户已登录后，可访问 B 的业务接口；B 侧不再编写重复的 interceptor/filter 做 JWT 校验。
- B 只信任 Envoy 完成本地验签后注入的 `X-Auth-* / X-Ctx-*` 主体信息；业务服务侧只读取这些 Header。
- 访问权限由 `aud/scopes` 控制，必要时通过 `ext_authz` 做细粒度授权与资源绑定校验。

### 4.2 参与方
- App（不可信客户端）
- Biz A Backend（受托业务平台，具备 SPIFFE 身份）
- Rust Issuer（签名/签发域，内部 mTLS，使用 SoftHSM2 执行签名）
- Go Exchange（兑换域，内部 mTLS）
- Envoy（Biz B 入口网关，本地 `jwt_authn` 验签 + `ext_authz` 授权）
- Biz B Backend（业务服务）

### 4.3 前置条件（引用全局不变量）
- 内部接口全部 mTLS + SPIFFE allowlist（见 2.1）
- AccessToken TTL 默认 15min（见 2.2）
- JWKS 端点为内部接口，仅允许 Envoy 拉取（见 2.1）
- Envoy strip 并重新注入 `X-Auth-* / X-Biz-* / X-Ctx-*`（见 2.3）
- 业务账号体系仍由 Biz A 自身负责，本场景仅做“门禁 + 身份透传”（与 BG-001 Out of Scope 一致）

### 4.4 端到端步骤表（Step Table）

| Step | Caller -> Callee     | Interface                        | Authn       | Input (摘要)                                                                  | Output (摘要)                                           | Store（建议）                                | OnFail              | Audit                                                |
| ---: | -------------------- | -------------------------------- | ----------- | --------------------------------------------------------------------------- | ----------------------------------------------------- | ---------------------------------------- | ------------------- | ---------------------------------------------------- |
|    1 | App -> Biz A         | `POST /login`（或既有登录流程）           | 业务侧         | 用户凭证/会话                                                                     | A 侧登录态（业务自管）                                          | 业务库                                      | 401/403             | 业务审计                                                 |
|    2 | App -> Biz A         | `POST /auth/token_for_b`（示例）     | 业务侧         | 目标资源/操作（例如 `scopes_request`）                                                | `access_token`（Bearer JWT）                            | 无                                        | 401/403             | 记录 user_id、target_b                                  |
|    3 | Biz A -> Rust Issuer | `POST /v1/internal/issue_ticket` | mTLS(SPIRE) | `subject{type:"user", id:"<A侧用户id>"}`, `target_aud="biz_b_api"`, `ctx{...}` | `grant_ticket`, `expires_in=60`                       | Redis `gt:{grant_id}`=SignedJWT（TTL=60s） | 401/403/500         | trace_id, client_id, spiffe_id, target_aud, decision |
|    4 | Biz A -> Go Exchange | `POST /v1/exchange/access_token` | mTLS(SPIRE) | `grant_ticket`                                                              | `access_token`（SignedJWT）                             | 原子核销 `GETDEL gt:{grant_id}`（一次性）         | 403/500             | jti, decision                                        |
|    5 | Biz A -> App         | `200 OK`                         | -           | `access_token`                                                              | 返回给 App（只暴露 access_token，不暴露 grant_ticket/entry_code） | 无                                        | -                   | 记录发放成功                                               |
|    6 | App -> Envoy(B)      | `GET/POST /b/api/...`            | Bearer JWT  | `Authorization: Bearer <access_token>`                                      | allow/deny                                            | Envoy 本地验签（无存储）                          | 401（缺token/验签失败/过期） | Envoy access log + jwt_authn 指标                      |
|    7 | Envoy(B) -> Go AuthZ | `POST /ext_authz/check`          | mTLS(SPIRE) | path/method + claims(sub/aud/scopes/ctx)                                    | allow/deny + header mutations                         | （可选缓存后续定）                                | 403 / 5xx（按策略处理）    | decision, reason                                     |
|    8 | Envoy(B) -> Biz B    | upstream route                   | （可选 mTLS）   | 注入 Header（X-Auth-* / X-Ctx-*）                                               | 业务响应                                                  | 无                                        | 5xx                 | upstream status/latency                              |

### 4.5 ctx 与 scopes 的最小约定（场景2）
- `aud` 必须为 `biz_b_api`（或 SoT 里约定的 B 侧 audience）。
- `scopes` 用于表达允许操作（字段名细节在 JWT-001 定型）。本场景至少区分：
  - 读：`biz_b.read`
  - 写：`biz_b.write`（如有）
- `ctx` 建议至少包含 A 侧用于审计/追踪的字段（例如 `tenant_id`、`project_id` 等），但必须遵循 “ctx 扁平键值对 + 白名单透传” 原则（OQ-002/JWT-001）。

### 4.6 关键校验点（必须）
1) **Client 身份校验（mTLS + allowlist）**  
- Biz A 调 Rust/Go 必须 mTLS；Rust/Go 仅接受登记过的 `spiffe_id -> client_id`。

2) **策略校验（control plane policy）**  
- Rust Issuer 校验：Biz A 是否允许申请 `target_aud=biz_b_api`；TTL 是否不超过 max_ttl；subject rule 是否允许该 `subject{type,id}` 生成合法 sub。

3) **一次性消费（防重放）**  
- GrantTicket 必须在 Go Exchange 侧原子核销（GETDEL/Lua），禁止重复兑换。

4) **Envoy 本地验签**  
- `jwt_authn` 校验签名、iss、aud、exp/iat、kid 对应 JWKS（JWKS 由 Rust 内部端点提供，仅 Envoy 拉取）。

5) **授权与资源绑定（ext_authz）**  
- 对需要细粒度授权的路由：按 `scopes`、`aud`、必要时 `ctx` 做 allow/deny。
- 默认不允许业务服务绕过 Envoy 直连；否则 Header 信任链失效。

### 4.7 失败表现（统一口径）
- A 申请票据被拒（policy deny/subject invalid）：Rust 返回 403（内部），A 返回业务侧错误。
- access_token 无效/过期：Envoy 返回 401。
- scope 不足：ext_authz 返回 403（可配置统一错误页/JSON）。
- 授权服务故障：按策略处理（建议默认 fail-closed，具体在 DEP-ENV/PLAN 定型）。

### 4.8 最小审计字段（建议）
- trace_id/request_id
- client_id、caller spiffe_id（内部调用）
- subject(type/id) 与最终 sub
- aud、scopes
- jti、iat/exp
- decision/reason（policy deny / expired / invalid signature / scope deny）
- Envoy 与上游延迟、状态码

### 4.9 可回归验收用例
1) 正常访问：A 登录后获取 access_token，访问 B 成功。
2) aud 错误：拿 `aud=form_platform` 的 token 访问 B，Envoy 401/403。
3) scope 不足：无 `biz_b.read` 访问读接口，403。
4) 过期 token：15min 后访问，401。
5) 禁用 client：禁用 Biz A 后，issue/exchange 请求失败（生效延迟目标在 NFR/PLAN 定型）。
---
## 5. 场景3：名医推荐服务（无账号体系）（必须）

### 5.1 目标
- 名医推荐服务自身不提供账号登录体系，但其接口必须具备安全门禁：只允许受信调用方访问。
- 调用方以“服务身份”为主（sub=service:*），必要时也可承载“用户身份”（sub=user:*）用于审计与按人限权（是否启用由策略决定）。
- 业务服务侧不实现重复鉴权逻辑：只读取 Envoy 注入的可信 Header（X-Auth-* / X-Ctx-*）。

### 5.2 参与方
- Caller Service：调用方业务服务（例如 Biz A / Biz B / 后台任务服务），具备 SPIFFE 身份
- Rust Issuer：签名/签发域（内部 mTLS，使用 SoftHSM2 执行签名）
- Go Exchange：兑换域（内部 mTLS）
- Envoy：名医服务入口网关（本地 jwt_authn + ext_authz）
- Featured Doctor Service：名医推荐服务（上游被保护服务）

### 5.3 前置条件（引用全局不变量）
- 内部接口全部 mTLS + SPIFFE allowlist（见 2.1）
- AccessToken TTL 默认 15min（见 2.2）
- JWKS 端点为内部接口，仅允许 Envoy 拉取（见 2.1）
- Envoy strip 并重新注入 `X-Auth-* / X-Biz-* / X-Ctx-*`（见 2.3）
- Audience Registry：`aud="featured_doctor_api"`（见 2.x）

### 5.4 端到端步骤表（Step Table）

| Step | Caller -> Callee | Interface | Authn | Input (摘要) | Output (摘要) | Store（建议） | OnFail | Audit |
|---:|---|---|---|---|---|---|---|---|
| 1 | Caller -> Rust Issuer | `POST /v1/internal/issue_ticket` | mTLS(SPIRE) | `subject{type:"service", id:"<caller_service_id>"}`, `target_aud="featured_doctor_api"`, `ctx{...}` | `grant_ticket`, `expires_in=60` | Redis `gt:{grant_id}`=SignedJWT（TTL=60s） | 401/403/500 | trace_id, client_id, spiffe_id, target_aud, decision |
| 2 | Caller -> Go Exchange | `POST /v1/exchange/access_token` | mTLS(SPIRE) | `grant_ticket` | `access_token`（SignedJWT） | 原子核销 `GETDEL gt:{grant_id}`（一次性） | 403/500 | jti, decision |
| 3 | Caller -> Envoy(Featured) | `GET /v1/featured-doctors?...`（示例） | Bearer JWT | `Authorization: Bearer <access_token>` | allow/deny | Envoy 本地验签（无存储） | 401（缺token/验签失败/过期） | Envoy access log + jwt_authn 指标 |
| 4 | Envoy -> Go AuthZ | `POST /ext_authz/check` | mTLS(SPIRE) | path/method + claims(sub/aud/scopes/ctx) | allow/deny + header mutations | （可选缓存后续定） | 403 / 5xx（按策略处理） | decision, reason |
| 5 | Envoy -> Featured Doctor Service | upstream route |（可选 mTLS）| 注入 Header（X-Auth-* / X-Ctx-*） | 业务响应 | 无 | 5xx | upstream status/latency |

### 5.5 ctx 与 scopes 的最小约定（场景3）
- `aud` 必须为 `featured_doctor_api`。
- `scopes` 用于表达允许操作，建议至少区分：
  - 读：`featured_doctor.read`
  - 管理：`featured_doctor.admin`（如存在导入/导出/管理端接口）
- `ctx` 用于审计/追踪字段（如 `tenant_id`、`project_id`、`trace_hint` 等），遵循 “ctx 扁平键值对 + 白名单透传”（OQ-002/JWT-001）。

### 5.6 关键校验点（必须）
1) **服务身份强约束（mTLS + allowlist）**
- Caller 调 Rust/Go 必须 mTLS；Rust/Go 仅接受登记过的 `spiffe_id -> client_id`。
- subject 生成规则：`subject{type:"service", id:"..."}` 必须满足该 client 的 subject rule，生成最终 `sub`（例如 `service:<id>`）。

2) **策略校验（control plane policy）**
- Rust Issuer 校验 Caller 是否允许申请 `target_aud=featured_doctor_api`，并限制 max_ttl。
- 若该服务只允许“特定调用方访问”，则应通过 policy 约束（client_id + target_aud + scopes）。

3) **Envoy 本地验签**
- `jwt_authn` 校验签名、iss、aud、exp/iat、kid 对应 JWKS（JWKS 由 Rust 内部端点提供，仅 Envoy 拉取）。

4) **授权（ext_authz 强制）**
- ext_authz 根据路由要求校验 `scopes`（read/admin）与必要的 ctx 条件（如租户/项目隔离策略）。

5) **防绕过**
- Featured Doctor Service 必须仅经 Envoy 暴露；直连绕过网关将破坏 Header 信任链。

### 5.7 失败表现（统一口径）
- 未授权服务申请票据：Rust 403（policy deny）。
- token 无效/过期：Envoy 401。
- scope 不足：ext_authz 403。
- 授权服务故障：按策略处理（建议默认 fail-closed，具体在 DEP-ENV/PLAN 定型）。

### 5.8 最小审计字段（建议）
- trace_id/request_id
- client_id、caller spiffe_id（内部调用）
- subject(type/id) 与最终 sub
- aud、scopes
- jti、iat/exp
- decision/reason（policy deny / expired / invalid signature / scope deny）
- Envoy 与上游延迟、状态码

### 5.9 可回归验收用例
1) 服务态访问：Caller 获取 access_token 后访问 `featured_doctor_api` 成功。
2) 未授权服务：不在 policy 的 client 申请票据失败（403）。
3) scope 不足：仅有 read scope 访问 admin 路由失败（403）。
4) 过期 token：15min 后访问失败（401）。
5) 禁用 client：禁用 caller 后，issue/exchange 立即失败（生效延迟目标在 NFR/PLAN 定型）。
---
## 6. 场景4：同业务 PC（Shiro）+ APP（Token）割裂 → 统一为“门禁 + 身份透传”（必须）

> 本场景不替换 Shiro/业务登录体系，只做统一门禁与身份透传：
> - PC 继续使用 Shiro 会话完成业务登录态
> - APP 继续使用自身登录态（或已有 token）
> - 两端对下游/受保护资源的访问，统一通过认证中心签发的 JWT（Cookie 或 Bearer），由 Envoy 验签并注入统一主体头

### 6.1 目标
- PC 与 APP 最终在下游业务服务看到的主体一致：`X-Auth-Subject`（以及 scopes/ctx），不再依赖前端传 `userId` 参数。
- 业务服务不再编写重复鉴权逻辑：只信 Envoy 注入 Header（strip 外部伪造头后再注入）。
- PC 访问第三方表单门禁可复用场景1（EntryCode → Gate → Cookie → Envoy）。
- 同一业务在不同终端的授权能力统一由 `aud/scopes` 表达，并由 ext_authz 做细粒度授权（如需要）。

### 6.2 参与方
- PC Browser（Shiro session）
- APP（Bearer token 或通过业务侧获取认证中心 token）
- Biz Backend（JeecgBoot/业务主服务，受托业务平台，具备 SPIFFE 身份）
- Rust Issuer（签名/签发域，内部 mTLS，使用 SoftHSM2 执行签名）
- Go Exchange（兑换域，内部 mTLS）
- Go Gate（外部门禁入口）
- Envoy（业务 API 入口网关，本地 jwt_authn + ext_authz）
- Biz Service（业务服务本体/下游服务）

### 6.3 前置条件（引用全局不变量）
- 内部接口全部 mTLS + SPIFFE allowlist（见 2.1）
- AccessToken TTL 默认 15min；SessionToken TTL 默认 20min（见 2.2）
- Envoy strip 并重新注入 `X-Auth-* / X-Biz-* / X-Ctx-*`（见 2.3）
- Audience Registry：本业务资源域 `aud` 必须为通用命名并登记（见 2.x）
  - 本节以 `core_business_api` 为例

### 6.4 推荐落地方式（统一由业务后端作为 Token Broker）
- PC 端：浏览器携带 Shiro session 请求 Biz Backend 获取访问 token（Bearer）或表单 gate_url。
- APP 端：APP 调 Biz Backend 获取 access_token（Bearer）用于访问业务 API。
- 下游业务服务：统一从 Envoy 注入头读取主体信息，不再信任前端传 userId。

> 说明：不建议让 Envoy 直接适配 Shiro session 做 ext_authz（复杂度高且容易导致边界膨胀）；优先由 Biz Backend 作为 broker。

### 6.5 端到端步骤表（PC 获取 AccessToken 访问业务 API）

| Step | Caller -> Callee | Interface | Authn | Input (摘要)                                                                                        | Output (摘要) | Store（建议） | OnFail | Audit |
| ---: | -------------------------- | -------------------------------- | ----------- | ------------------------------------------------------------------------------------------------- | ------------------------------- | ---------------------------------------- | ---------------- | --------------------------------------------- |
| 1 | PC -> Biz Backend | `POST /pc/token`（示例） | Shiro（业务侧） | Shiro session cookie                                                                              | `access_token`（Bearer JWT） | 无 | 401/403 | 业务审计（user_id/role） |
| 2 | Biz Backend -> Rust Issuer | `POST /v1/internal/issue_ticket` | mTLS(SPIRE) | `subject{type:"user", id:"<from Shiro principal>"}`, `target_aud="core_business_api"`, `ctx{...}` | `grant_ticket`, `expires_in=60` | Redis `gt:{grant_id}`=SignedJWT（TTL=60s） | 401/403/500 | trace_id, client_id, spiffe_id, aud, decision |
| 3 | Biz Backend -> Go Exchange | `POST /v1/exchange/access_token` | mTLS(SPIRE) | `grant_ticket`                                                                                    | `access_token`（SignedJWT） | 原子核销 `GETDEL gt:{grant_id}` | 403/500 | jti, decision |
| 4 | PC -> Envoy(Biz) | `GET/POST /api/...` | Bearer JWT | `Authorization: Bearer <access_token>`                                                            | allow/deny | Envoy 本地验签 | 401 | envoy jwt_authn |
| 5 | Envoy -> Go AuthZ | `POST /ext_authz/check` | mTLS(SPIRE) | path/method + claims(sub/aud/scopes/ctx)                                                          | allow/deny + header mutations |（可选缓存后续定）| 403 / 5xx（按策略处理） | decision/reason |
| 6 | Envoy -> Biz Service | upstream route |（可选 mTLS）| 注入 `X-Auth-* / X-Ctx-*`                                                                           | 业务响应 | 无 | 5xx | upstream status/latency |

### 6.6 端到端步骤表（APP 获取 AccessToken 访问业务 API）
> 与 PC 类似，仅 Step 1 的“业务侧认证方式”不同。

| Step | Caller -> Callee | Interface | Authn | Input (摘要) | Output (摘要) | Store | OnFail | Audit |
|---:|---|---|---|---|---|---|---|---|
| 1 | APP -> Biz Backend | `POST /app/token`（示例） | 业务侧（APP 登录态） | APP 侧登录态/会话 | `access_token` | 无 | 401/403 | 业务审计 |
| 2~6 | 同 6.5 Step 2~6 | - | - | - | - | - | - | - |

### 6.7 PC/APP 进入第三方表单门禁（复用场景1）
- PC/APP -> Biz Backend：请求“表单跳转链接”（业务侧已认证）
- Biz Backend：按场景1执行：
  - issue_ticket（aud=form_platform）→ exchange_entry_code → 返回 `gate_url`
- PC/APP WebView/Browser：访问 `gate_url`，Go Gate 种 `session_token` Cookie 并 302，Envoy 门禁通过

### 6.8 关键校验点（必须）
1) **统一主体来源**
- PC：subject 必须来自 Shiro principal（业务侧认证结果），不得由前端传入 userId 拼接。
- APP：subject 必须来自 APP 登录态对应的业务侧身份。

2) **禁止前端 userId 越权（必须形成团队规范）**
- 业务服务对“用户自身数据接口”必须从 `X-Auth-Subject` 推导 userId；任何前端传入的 userId：
  - 要么忽略；
  - 要么做一致性校验（若不一致则拒绝 403）。

3) **aud/scopes 统一授权**
- `aud="core_business_api"`（示例）必须来自 Audience Registry。
- `scopes` 用于表达不同端/角色差异（字段细节在 JWT-001 定型），由 ext_authz 或业务服务基于注入头统一限制。

4) **防绕过**
- Biz Service 必须只经 Envoy 暴露；直连绕过网关将破坏 Header 信任链。

### 6.9 失败表现（统一口径）
- PC 未登录：Biz Backend 返回 401（业务侧）。
- token 无效/过期：Envoy 返回 401。
- scope 不足：ext_authz 403。
- 前端伪造 userId 越权：业务服务拒绝 403（或忽略参数后返回当前用户数据）。

### 6.10 最小审计字段（建议）
- trace_id/request_id
- client_id、caller spiffe_id（内部调用）
- subject(type/id) 与最终 sub
- aud、scopes
- jti、iat/exp
- decision/reason（policy deny / expired / invalid signature / scope deny / idor_attempt）
- Envoy 与上游延迟、状态码

### 6.11 可回归验收用例
1) PC 登录后访问“用户自己的数据”接口：不传 userId 也能正确返回；传他人 userId 触发 403（或被忽略仍返回本人数据）。
2) APP 同接口行为一致（统一主体）。
3) PC 获取表单 gate_url：正常进入表单；重复打开同 gate_url 失败（重放阻断）。
4) scope 限制：普通用户 token 访问管理员接口失败（403）。
---
## 7. Webhook 回调（认证聚焦，业务闭环已在既有系统实现）

### 7.1 定位与边界
- Webhook 不纳入本项目票据体系（不走 GrantTicket/EntryCode/SessionToken/AccessToken）。
- Webhook 的核心关注点：**只允许可信工作负载发送（mTLS + SPIFFE）**，以及**重复投递可安全返回成功**。
- Receiver 的业务处理闭环（Receipt + Outbox 同事务落库 → MQ 异步）由既有系统保证；本文不重复定义业务状态机。

### 7.2 认证方式（必须）
- Webhook 属于“服务到服务调用”，因此 **必须 mTLS（SPIRE）+ SPIFFE allowlist**。
- X.509-SVID 的 SPIFFE ID 位于证书的 URI SAN 中（用于标识调用方身份）。  
- Envoy 必须在下游 mTLS 校验阶段对调用方证书做 SAN 匹配（allowlist），未匹配直接拒绝。

> 说明：X.509-SVID 必须包含一个 URI SAN（即一个 SPIFFE ID）。  
> Envoy 支持通过 SAN matcher 校验对端证书的 Subject Alternative Name 是否匹配配置规则。

### 7.3 推荐链路（认证最小闭环）
1) Sender（表单平台）从本机 SPIRE Agent 获取 X.509-SVID，向 Envoy 发起 mTLS 请求。
2) Envoy 校验证书链与 SPIFFE ID（URI SAN）是否在 allowlist 内：
   - 失败：401/403
   - 成功：转发到 Receiver
3) Receiver 不再做额外 token 校验；只处理 payload，并交给既有 Receipt/Outbox/MQ 闭环。

### 7.4 幂等与返回码（与你的实现对齐）
- Sender 的幂等键：`event_id = correlation_id`
- 重复投递：Receiver 视为幂等成功，统一返回 **200**
- 处理失败：返回 5xx 触发 Sender 重试（是否重试由发送方策略决定）

### 7.5 最小审计字段（建议）
- request_id/trace_id
- caller spiffe_id（从 mTLS 证书 URI SAN 得出）
- event_id（=correlation_id）
- processing_status（accepted/duplicate/failed）
- last_error（如失败）
---
## 8. 未知场景推演清单（必须）

> 目的：保证本认证体系具备通用性，避免只在“表单门禁/单一业务”场景可用。  
> 本章只列“必须验证项”，不在此展开实现细节；实现细节分别落到 Contracts（JWT-001）、Deploy（DEP-ENV/DEP-SPIRE）与 Runbooks。

### 8.1 推演清单（逐条可验证）

| ID    | 场景                                    | 为什么要测                                              | 影响组件                            | 验证方式（怎么测）                                      | 验收口径（通过标准）                                                                  | 归属文档             |
| ----- | ------------------------------------- | -------------------------------------------------- | ------------------------------- | ---------------------------------------------- | --------------------------------------------------------------------------- | ---------------- |
| U-001 | WebView Cookie 策略差异（Android/iOS/不同内核） | WebView 对 Cookie/302/跨域支持差异大，常导致门禁失败               | Go Gate / Envoy / Cookie        | 真实设备 + 抓包：首次 gate 302 后是否携带 `session_token`    | 进入 `/s/*`、`/q/*` 全流程可用；失败能落到统一错误页                                           | FL-001/DEP-ENV   |
| U-002 | iframe 嵌入（SameSite/第三方 Cookie）        | iframe 常触发第三方 Cookie 限制，`SameSite=Lax` 可能不发 Cookie | Go Gate / Cookie / Envoy        | 用 iframe 嵌入表单页，验证 cookie 是否发送；切换 SameSite 策略对比 | same-site iframe：必须可用；    <br> cross-site iframe：不承诺；需提供降级策略（弹新页/顶层跳转/同站代理） | FL-001/JWT-001   |
| U-003 | 跨域跳转 target 参数篡改                      | target 被篡改可能导致 open redirect 或资源越权                 | Go Gate / ext_authz             | 篡改 target（不同路径/不同 formKey）                     | 只允许白名单路径前缀；formKey 与 ctx 绑定不一致必须拒绝                                          | FL-001/DEP-ENV   |
| U-004 | 下载/导出类接口（Content-Disposition）         | 下载通常走新窗口/不同请求链路，Cookie/Bearer 行为不同                 | Envoy / jwt_authn               | 下载链接直接访问、复制链接访问、断点续传                           | 需要鉴权的下载必须通过；无票访问必须 401/403                                                  | FL-001/DEP-ENV   |
| U-005 | WebSocket / SSE 长连接鉴权                 | 长连接的 token 续期与验签点不同，容易绕过或断连                        | Envoy / jwt_authn / ext_authz   | 建立 WS/SSE 连接，测试 token 过期/刷新后的行为                | 明确策略：连接建立时验签；过期后如何处理（断开/续签）                                                 | FL-001/JWT-001   |
| U-006 | Token 过期与时钟漂移（clock skew）             | iat/exp 校验在分布式环境常遇到时钟漂移                            | Envoy / jwt_authn               | 人为调整 Envoy/服务时间偏移（±X 秒）                        | 有明确允许偏移窗口；超窗必须拒绝且可观测                                                        | JWT-001/DEP-ENV  |
| U-007 | JWKS 轮换（kid 切换 + GRACE 窗口）            | 轮换是必然：旧 token 在 GRACE 期间仍需验证                       | Rust JWKS / Envoy cache         | 模拟轮换：新 token 使用新 kid；旧 token 在窗口内仍可验           | 轮换不致中断；过窗旧 token 必须失败；日志可追溯                                                 | SEC-003/DEP-ENV  |
| U-008 | 黑名单/紧急禁用生效延迟                          | 禁用 client/user/jti 需要可控延迟，否则事故扩大                   | Control Plane / Envoy/ext_authz | 禁用 client 后立即请求签发/访问                           | 达到约定生效延迟（例如 <5s）并有审计记录                                                      | PLAN-001/SEC-001 |
| U-009 | ctx 扁平化与 Header 体积上限                  | Header 注入过大可能导致 431/丢头/代理拒绝                        | JWT-001 / Envoy                 | 构造最大 ctx，验证注入行为与限流/拒绝                          | ctx 超限必须在签发侧拒绝（4xx），不能打爆 Envoy                                              | JWT-001          |
| U-010 | 多租户 tenant_id 贯穿                      | 多租户是常见通用需求，必须验证隔离策略                                | ext_authz / ctx                 | tenant_id 写入 ctx；请求跨租户资源                       | 跨租户必须拒绝；审计记录包含 tenant_id                                                    | JWT-001/SEC-001  |
| U-011 | “同 correlation_id 多事件” webhook 幂等风险   | 仅 correlation_id 幂等可能吞掉后续事件                        | Webhook Receiver                | 重复投递（同 correlation_id+form_key）必须幂等成功          | 业务闭环不丢事件；重复与不同事件能区分                                                         | Webhook/既有实现     |
| U-012 | 服务间调用的最小暴露面（绕过 Envoy）                 | 直连绕过网关会破坏 Header 信任链                               | 网络拓扑/部署                         | 直接请求上游服务端口（绕过 Envoy）                           | 生产必须无法绕过（网络/防火墙/仅监听内网）                                                      | DEP-ENV/Runbooks |
| U-013 | 频繁刷新/高并发按钮狂点（Gate/EntryCode）          | entry_code 双花/并发消费是高频真实问题                          | Go Gate / Redis                 | 并发 1000 次同 entry_code 访问                       | 仅 1 次成功，其余稳定失败；无脏数据                                                         | FL-001/Go 实现     |
| U-014 | 访问控制落点（jwt_authn vs ext_authz）        | 哪些路由必须本地验签，哪些需外部授权要清晰                              | Envoy                           | 列出路由矩阵，分别测试无 token/无 scope/无绑定                 | 路由矩阵与行为一致；错误码统一                                                             | DEP-ENV/SEC-001  |
| U-015 | SoftHSM2 可用性与恢复（不展开实现）                | 引入 SoftHSM2 后必须验证重启/恢复与签名稳定性                       | Rust Issuer / SEC-003           | 模拟 token 目录恢复、进程重启后签名                          | 不中断签发；kid/公钥一致性可控；失败可告警                                                     | SEC-003/Runbooks |

### 8.2 推演输出要求（本章约束）
- 每个 U-xxx 必须给出：验证步骤、预期结果、失败时的观测点（日志/指标/错误码）。
- 推演结果若引起“结论变更”，必须走 CHG（decisions.md）。
---
## 9. 统一失败矩阵（必须）

> 约定：外部=浏览器/WebView；内部=服务到服务（mTLS）。
> 对外返回码以用户体验优先；对内返回码以可诊断为优先。

### 9.1 失败类型与对外行为

| 类别              | 典型失败点                                             | 对外（浏览器/WebView）行为         | 对内（服务到服务）行为 | 是否可重试    | 观测点（必须）                               |
| --------------- | ------------------------------------------------- | ------------------------- | ----------- | -------- | ------------------------------------- |
| 认证失败（mTLS）      | 内部接口证书无效/非 allowlist SPIFFE                       | 不涉及                       | 401/403     | 否        | caller spiffe_id、deny reason          |
| 策略拒绝            | client 无权申请 target_aud / 超 TTL / subject rule 不匹配 | 不涉及                       | 403         | 否        | client_id、target_aud、policy_id、reason |
| GrantTicket 无效  | 过期/不存在/已被兑换                                       | 不涉及                       | 403         | 否        | grant_id、idempotency_hit              |
| EntryCode 无效/已用 | 过期/已核销/不存在                                        | 302 到统一错误页（或 403）         | 不涉及         | 否        | entry_id、client_ip、ua                 |
| JWT 验签失败        | cookie/bearer 缺失、签名不对、exp/iat 不合法                 | 401（可配置跳错误页）              | 401         | 否        | jwt_authn stats、kid、reason            |
| aud 不匹配         | token 的 aud 与路由域不符                                | 401/403（建议 401）           | 401/403     | 否        | aud、route                             |
| scope 不足        | ext_authz 判定 scope 不足                             | 403（可配置错误页）               | 403         | 否        | decision=deny、required_scope          |
| 资源绑定失败          | formKey/serial 与 ctx 不一致                          | 403（可配置错误页）               | 403         | 否        | binding_result、ctx 摘要                 |
| JWKS 获取失败       | Envoy 拉取 JWKS 超时/失败                               | 依赖缓存：有缓存则继续；无缓存则 401      | 不涉及         | 是（系统恢复后） | jwks fetch error、cache_age            |
| Redis 故障        | gate/兑换依赖 Redis 不可用                               | gate 返回错误页/503            | 503         | 是        | redis latency/error、连接池               |
| SoftHSM2 故障     | Issuer 签名失败/slot 不可用                              | 不涉及                       | 503         | 是（恢复后）   | hsm op error、slot/label               |
| ext_authz 故障    | 授权服务 5xx/超时                                       | 取决于策略：fail-closed=403/503 | 取决于策略       | 是        | ext_authz timeout、5xx                 |
| 上游故障            | 表单平台/业务服务 5xx                                     | 5xx                       | 5xx         | 是（看上游）   | upstream status/latency               |
| Webhook 身份非法    | mTLS 不通过                                          | 401/403                   | 401/403     | 否        | caller spiffe_id                      |
| Webhook 重复投递    | correlation_id+form_key 冲突                        | 200（幂等成功）                 | 200         | 否        | idempotency_hit=true                  |

### 9.2 统一错误页/错误体（外部）
- Go Gate 的错误页：用于 entry_code 无效/已用/缺参等用户可见错误。
- Envoy 侧 401/403：可配置跳转到统一错误页（或返回 JSON，取决于接入端类型）。
- 统一要求：错误页必须包含 `request_id`（便于定位日志）。
- 页面类路由（如 `/s/*`、`/q/*`）：401/403 统一 302 跳转到 `/_auth/error`（HTML），错误页必须展示 `request_id`。
- API 类路由（如 `/api/*`、`/v1/*`）：401/403 统一返回 JSON 错误体，包含 `request_id`，不做 302。

### 9.3 必须统一的观测字段（跨组件）
- request_id / trace_id
- client_id、caller spiffe_id（内部调用）
- target_aud / aud
- jti / kid（如涉及 JWT）
- decision（allow/deny）与 reason
- latency（issuer/exchange/gate/authz/envoy/upstream）