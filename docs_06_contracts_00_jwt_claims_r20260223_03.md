# JWT-001 Token Claims & Header Contract（SoT）
- Doc ID: JWT-001
- Status: FINAL
- Owner: IU
- Last Updated: 2026-02-23
- Depends On: FL-001, ARCH-001, PLAN-001
- Logical Path: docs/06_contracts/00_jwt_claims.md
- Revision: r20260223_03
- Supersedes: r20260223_02

---

## 1. 目标与范围
- 固化本项目所有 JWT（SessionToken / AccessToken）的 **Header / Claims / 校验规则 / ctx 约束 / Envoy 注入头契约**，作为后续 API-001 与实现的唯一依据。
- 关闭 OQ-002：ctx 形态、大小、透传策略在本文冻结。

---

## 2. Token 类型与载体

### 2.1 AccessToken（Bearer）
- 载体：`Authorization: Bearer <JWT>`
- 默认 TTL：15min（与 FL-001 一致）
- 使用场景：API 调用、服务间调用（场景2/3/4）

### 2.2 SessionToken（Cookie）
- 载体：`Set-Cookie: session_token=<JWT>; HttpOnly; Secure; SameSite=Lax; Path=/`
- 默认 TTL：20min（与 FL-001 一致）
- 使用场景：页面门禁（场景1），浏览器/WebView 自动携带

> 说明：两类 token 使用同一 JWT 结构，仅载体不同。

---

## 3. JWT Header（固定）
- `typ`: `"JWT"`
- `alg`: `"EdDSA"`（Ed25519）
- `kid`: `<key id>`（必须；用于从 JWKS 选择公钥）

---

## 4. JWT Payload（Claims）

> Required / Recommended / Optional 分级：  
> - Required：缺失即拒绝（401）。  
> - Recommended：建议具备，用于审计/授权。  
> - Optional：非默认必需，仅在扩展场景启用。

### 4.1 Required
- `iss`：签发者（string），固定：`"xjiot-auth-center"`
- `sub`：主体（string），格式见 4.4
- `aud`：受众（string），必须来自 Audience Registry（单值）
- `jti`：全局唯一 Token ID（string，推荐 UUIDv4）
- `iat`：签发时间（number，Unix 秒，UTC）
- `exp`：过期时间（number，Unix 秒，UTC）
- `ctx`：业务上下文（object，扁平键值对，规则见第 5 章；允许为空对象 `{}`）

### 4.2 Recommended
- `azp`：Authorized Party（string），发起申请的 `client_id`（例如 `jeecg-boot` / `biz-a`）
- `scopes`：权限范围（string），空格分隔，例如：`"biz_b.read biz_b.write"`

### 4.3 Optional
- `ver`：Token 版本号（number），默认 `1`（用于未来兼容演进）
- `nbf`：Not Before（默认不启用）
- `nonce`：特定防重放场景使用（默认不启用）

### 4.4 `sub` 格式（固定约束）
- `sub` 必须为认证中心生成的规范字符串，推荐前缀区分主体类型：
  - 用户：`user:<id>`
  - 服务：`service:<id>`
- 下游禁止信任前端传入的 userId，必须以 `sub` 为唯一主体来源（见 FL-001 场景4）。

---

## 5. ctx 约束（关闭 OQ-002）

> ctx 必须是 **扁平 Map<string,string>**，禁止嵌套对象/数组。  
> Issuer 在签发时强校验，超限直接 4xx 拒绝（不能把畸形输入带进 Envoy）。  
> 说明：ctx 总大小上限 2KB 主要为保证 **SessionToken（Cookie）稳定**；JWT base64url 编码会膨胀约 33%，ctx 过大会触发浏览器/WebView 单 cookie 大小限制风险。

### 5.1 Key 规则
- 字符集：`[a-z][a-z0-9_]{0,31}`（小写 + 下划线）
- 最大长度：32

### 5.2 Value 规则
- 仅字符串
- 最大长度：256（字符）
- 禁止包含换行符 `\r` / `\n`（避免 header 注入与日志污染风险）

### 5.3 Entries 与总大小
- 最大条目数：20
- ctx JSON 序列化后总大小上限：2KB（2048 bytes）

### 5.4 预留 key（通用建议）
- 表单门禁建议使用：
  - `form_key`
  - `correlation_id`
  - `action`（`FILL` / `QUERY`）
  - `allowed_serial`（可选，用于查询限定）
- 多租户/项目建议：
  - `tenant_id`（可选）
  - `project_id`（可选）

---

## 6. aud（Audience）规则
- `aud` 必须为单值 string，且必须在 Audience Registry 中存在。
- 当前预置（来自 ARCH-001）：
  - `form_platform`
  - `biz_b_api`
  - `featured_doctor_api`
  - `core_business_api`
- 禁止在 `aud` 中携带环境、域名、IP、端口。

---

## 7. 验签与时间规则（Envoy + 下游一致）
- 验签算法：EdDSA（Ed25519）
- JWKS：
  - 由 Rust Issuer 提供 **内部端点**
  - Envoy 通过 **mTLS（SPIRE）** 拉取并缓存
  - `cache_duration` 默认：300s
- clock skew：允许 ±60s（用于 iat/exp 校验容忍）
- Key 轮换：允许 GRACE 窗口（旧 `kid` 在窗口内仍可验）；轮换窗口策略与 HSM 运维在 `SEC-003` 固化。

---

## 8. Envoy 提取与 Header 注入契约（强约束）

> 目标：下游服务不解析 JWT，只读取 Envoy 注入头；外部同名 header 必须被 strip。

### 8.1 必注入 Header（所有受保护路由）
- `X-Auth-Subject: <sub>`
- `X-Auth-Audience: <aud>`
- `X-Auth-Client-Id: <azp>`（若 azp 缺失则省略）
- `X-Auth-Scopes: <scopes>`（若 scopes 缺失则省略）

### 8.2 ctx 透传策略（默认白名单）
- 仅白名单 ctx key 才允许注入为 header（避免 header 爆炸）：
  - 默认白名单：`form_key`, `correlation_id`, `allowed_serial`, `action`, `tenant_id`, `project_id`
- 头部格式：
  - `X-Ctx-<Kebab-Case-Key>: <value>`
- 表单场景别名头（可选，但建议保留一致性）：
  - `X-Biz-Form-Key`（= ctx.form_key）
  - `X-Biz-Correlation-Id`（= ctx.correlation_id）
  - `X-Biz-Allowed-Serial`（= ctx.allowed_serial）

### 8.3 Strip 规则（必须）
- Envoy 在入口必须 strip 掉外部请求里已有的 `X-Auth-* / X-Biz-* / X-Ctx-*`，再重新注入。

---

## 9. 拒绝策略（统一）
- 缺失 token / token 无效 / 验签失败 / exp 超时：401
- aud 不匹配、scopes 不足、资源绑定失败：403
- 页面路由：401/403 → 302 `/_auth/error`（含 request_id）
- API 路由：401/403 → JSON 错误体（含 request_id，不 302）
- ext_authz 故障：受保护路由 fail-closed（与 FL-001/PLAN-001 一致）

---

## 10. 兼容与演进
- Claims 的新增必须向后兼容；删除/改名必须走 CHG。
- `ver` 用于未来 claims 演进分支。

---

## 11. 附录：示例（非规范的一部分）
### 11.1 示例 Claims（AccessToken）
```json
{
  "iss": "xjiot-auth-center",
  "sub": "user:10086",
  "aud": "biz_b_api",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "iat": 1761210000,
  "exp": 1761210900,
  "azp": "biz-a",
  "scopes": "biz_b.read",
  "ctx": {
    "tenant_id": "t1",
    "project_id": "p1"
  }
}