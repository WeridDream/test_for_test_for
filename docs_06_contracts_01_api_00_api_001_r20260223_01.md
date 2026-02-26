# API-001 Issuer / Exchange / Gate / AuthZ Interfaces（SoT）  
- Doc ID: API-001  
- Status: FINAL  
- Owner: IU  
- Last Updated: 2026-02-23  
- Depends On: FL-001, JWT-001, ARCH-001  
- Logical Path: docs/06_contracts/01_api/00_api_001.md  
- Revision: r20260223_01  
- Supersedes: N/A  
  
---  
  
## 0. 总览（接口分层与信任边界）  
  
本项目 API 分为两层：  
  
### 0.1 外部（Untrusted，浏览器/WebView/PC/APP，不走 mTLS）  
- `GET /_auth/gate`：EntryCode 一次性核销 → Set-Cookie(session_token=JWT) → 302 跳转  
- `GET /_auth/error`：统一错误页（HTML）  
  
### 0.2 内部（Trusted Workload，服务到服务调用，全部 mTLS + SPIFFE allowlist）  
- `POST /v1/internal/issue_ticket`：Client → Rust Issuer（签发 GrantTicket）  
- `GET /.well-known/jwks.json`：Envoy → JWKS Provider（Rust Issuer）（内部 mTLS）  
- `POST /v1/exchange/entry_code`：Client → Go Exchange（GrantTicket → EntryCode）  
- `POST /v1/exchange/access_token`：Client → Go Exchange（GrantTicket → AccessToken）  
- `POST /ext_authz/check`：Envoy → Go AuthZ（授权与资源绑定；fail-closed）  
  
---  
  
## 1. 协议与版本  
- 文档规范：本文件为 SoT 文本契约；后续可生成 OpenAPI 3.1 YAML。  
- 编码：UTF-8  
- 时间：UTC（iat/exp 为 Unix 秒；clock skew 见 JWT-001）  
  
---  
  
## 2. 通用约定  
  
### 2.1 Request ID  
- 入参：客户端/Envoy 建议携带 `x-request-id`；缺失则服务端生成。  
- 出参：必须回显 `x-request-id`。  
- JSON 错误体必须包含 `request_id`。  
  
### 2.2 内部接口统一 JSON 响应封装（mTLS 接口）  
成功：  
```json  
{  
  "code": "OK",  
  "message": "success",  
  "request_id": "req_xxx",  
  "data": {}  
}
```

错误：
```json
{  
  "code": "AUTH_INVALID_ARGUMENT",  
  "message": "human readable message",  
  "request_id": "req_xxx",  
  "details": { "field": "reason" }  
}
```
### 2.3 错误码最小集（内部接口）

- `AUTH_INVALID_ARGUMENT`（400）
    
- `AUTH_UNAUTHORIZED`（401：mTLS/身份失败）
    
- `AUTH_FORBIDDEN`（403：策略/权限/重放/资源绑定失败）
    
- `AUTH_NOT_FOUND`（404）
    
- `AUTH_RATE_LIMITED`（429）
    
- `AUTH_INTERNAL`（500）
    

### 2.4 内部接口认证（必须）

- 所有内部接口必须启用 mTLS（SPIRE）。
    
- 服务端必须从客户端证书解析 SPIFFE ID（URI SAN），并命中 allowlist（`spiffe_id -> client_id`）。
    
- 失败直接 401/403（按实现选择，但建议：证书无效=401；身份不在 allowlist=403）。
    

---

## 3. Rust Issuer API（内部）

### 3.1 POST /v1/internal/issue_ticket

- 调用方：业务平台/服务端（Client）
    
- 认证：mTLS(SPIRE) + SPIFFE allowlist
    
- 目标：
    
    1. 校验 client/policy/subject rule
        
    2. 生成 SignedJWT（**遵循 JWT-001**）（EdDSA/Ed25519，SoftHSM2/PKCS#11）
        
    3. 写入 Redis 映射：`gt:{grant_ticket}` → `SignedJWT`（TTL=60s）
        
    4. 返回 `grant_ticket`
        

#### Request
```json
{  
  "subject": { "type": "user", "id": "10086" },  
  "target_aud": "form_platform",  
  "requested_scopes": "form.fill form.query",  
  "requested_token_ttl_seconds": 1200,  
  "ctx": {  
    "form_key": "8m5OQppf",  
    "correlation_id": "CORR_123",  
    "action": "FILL",  
    "allowed_serial": "SER_1"  
  }  
}
```


字段说明：

- `subject`（required）
    
    - `type`: `"user" | "service"`
        
    - `id`: 业务侧主体 id（string）
        
    - Issuer 根据 subject rule 生成最终 `sub`（写入 JWT-001 的 `sub`）
        
- `target_aud`（required）：必须存在于 Audience Registry（ARCH-001）
    
- `requested_scopes`（optional）：空格分隔 string；写入 JWT-001 的 `scopes`
    
- `requested_token_ttl_seconds`（optional）：最终 token TTL；必须 ≤ policy.max_ttl_sec
    
- `ctx`（required，可为空对象）：必须符合 JWT-001 ctx 约束（扁平/2KB/条目数等）
    

#### Response（200）
```json
{  
  "code": "OK",  
  "message": "success",  
  "request_id": "req_xxx",  
  "data": {  
    "grant_ticket": "gt_xxxxxxxxx",  
    "expires_in": 60  
  }  
}
```

#### Errors

- 400：ctx/scopes/ttl 格式错误或超限
    
- 401：mTLS 失败/无法解析 SPIFFE ID
    
- 403：策略不允许（aud 不允许、subject rule 不匹配、ttl 超过 max_ttl）
    
- 500：内部错误
    

---

### 3.2 GET /.well-known/jwks.json（内部）

- 调用方：Envoy（jwt_authn remote_jwks）
    
- 认证：mTLS(SPIRE) + SPIFFE allowlist（仅允许 Envoy 工作负载）
    
- 目标：提供 Ed25519 公钥集合（JWKS），供 Envoy 验签使用
    

#### Response（200）
```json
{  
  "keys": [  
    {  
      "kty": "OKP",  
      "crv": "Ed25519",  
      "kid": "kid_20260223_01",  
      "use": "sig",  
      "alg": "EdDSA",  
      "x": "BASE64URL_PUBLIC_KEY"  
    }  
  ]  
}
```

#### Errors

- 401/403：mTLS/allowlist 不通过
    
- 500：内部错误
    

---

## 4. Go Exchange API（内部）

### 4.1 POST /v1/exchange/entry_code

- 调用方：业务平台/服务端（Client）
    
- 认证：mTLS(SPIRE) + SPIFFE allowlist
    
- 目标：
    
    1. 原子核销 GrantTicket（一次性）：`GETDEL gt:{grant_ticket}`
        
    2. 生成 EntryCode（一次性，TTL=60s）并写入 Redis：`ec:{entry_code}` → `SignedJWT`
        
    3. 返回 `gate_url`
        

#### Request
```json
{  
  "grant_ticket": "gt_xxxxxxxxx",  
  "target": "/s/8m5OQppf?correlationId=CORR_123"  
}
```

`target` 约束（必须）：

- 必须是**相对路径**（以 `/` 开头）
    
- 必须命中 allow prefixes：`/s/` 或 `/q/`
    
- 禁止：`http://`、`https://`、`//`、包含 `\r`/`\n`（防 open redirect 与 header 注入）
    

#### Response（200）
```json
{  
  "code": "OK",  
  "message": "success",  
  "request_id": "req_xxx",  
  "data": {  
    "entry_code": "ec_xxxxxxxxx",  
    "expires_in": 60,  
    "gate_url": "https://<public-host>/_auth/gate?entry_code=ec_xxxxxxxxx&target=/s/8m5OQppf?correlationId=CORR_123"  
  }  
}
```

#### Errors

- 400：target 非法
    
- 403：grant_ticket 无效/过期/已用
    
- 500：内部错误
    

---

### 4.2 POST /v1/exchange/access_token

- 调用方：业务平台/服务端（Client）
    
- 认证：mTLS(SPIRE) + SPIFFE allowlist
    
- 目标：原子核销 GrantTicket（一次性）→ 返回 AccessToken（Bearer JWT）
    

#### Request
```json
{  
  "grant_ticket": "gt_xxxxxxxxx"  
}
```

#### Response（200）（返回的 access_token 为 JWT-001 定义的 AccessToken。）
```json
{  
  "code": "OK",  
  "message": "success",  
  "request_id": "req_xxx",  
  "data": {  
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLiJ9...",  
    "token_type": "Bearer",  
    "expires_in": 900  
  }  
}
```

#### Errors

- 403：grant_ticket 无效/过期/已用
    
- 500：内部错误
    

---

## 5. Go Gate API（外部）

### 5.1 GET /_auth/gate

- 调用方：Browser/WebView（外部）
    
- 认证：None（外部）
    
- 目标：
    
    1. Lua 原子核销 EntryCode（一次性）：`GET ec:{entry_code}` + `DEL ec:{entry_code}`
        
    2. `Set-Cookie(session_token=<JWT>; HttpOnly; Secure; SameSite=Lax; Path=/)`
        
    3. `302 Location: <target>`
        

#### Query

- `entry_code`（required）
    
- `target`（required；规则同 4.1 的 target 约束）
    

#### Success（302）

- `Set-Cookie: session_token=<JWT>; HttpOnly; Secure; SameSite=Lax; Path=/`
    
- `Location: <target>`
    

#### Failure（用户友好）

- entry_code 无效/已用：302 到 `/_auth/error`
    
- target 非法：302 到 `/_auth/error`
    

---

### 5.2 GET /_auth/error

- 调用方：Browser/WebView（外部）
    
- 认证：None
    
- 返回：HTML 错误页（必须包含 request_id，便于排障）
    

建议 Query：

- `code`：错误码（optional）
    
- `request_id`：定位日志（optional）
    
- `msg`：展示用短消息（optional；服务端必须长度上限 + HTML 转义）
    

---

## 6. Go AuthZ（Envoy ext_authz，内部）——选择 A：只读 Envoy 注入头

### 6.1 POST /ext_authz/check

- 调用方：Envoy（内部）
    
- 认证：mTLS(SPIRE) + SPIFFE allowlist（仅允许 Envoy workload）
    
- 前置条件（必须）：
    
    1. Envoy 已对原始请求完成 `jwt_authn` 验签
        
    2. Envoy 已执行 strip 外部伪造的 `X-Auth-* / X-Biz-* / X-Ctx-*`
        
    3. Envoy 已注入本项目约定的 `X-Auth-* / X-Ctx-* / X-Biz-*`（见 JWT-001）
        

#### 6.1.1 AuthZ 依赖的输入（强约束）

AuthZ **只读取**以下信息：

- `X-Auth-Subject`（required）
    
- `X-Auth-Audience`（required）
    
- `X-Auth-Scopes`（optional）
    
- ctx 透传头（可选）：`X-Ctx-*` +（表单别名）`X-Biz-*`
    
- 原始请求属性（required）：方法与路径
    

> 方法与路径必须由 Envoy 在发起 ext_authz 请求时显式添加两个头（避免依赖 Envoy 内部默认行为差异）：

- `X-Authz-Method: <original-method>`
    
- `X-Authz-Path: <original-path>`
    

（这两项通过 Envoy ext_authz 配置 `request_headers_to_add` 注入。）

#### 6.1.2 Request（AuthZ Service 接收的 HTTP Request）

- Method：POST
    
- Path：`/ext_authz/check`
    
- Headers（最小集）：
    
    - `X-Authz-Method`
        
    - `X-Authz-Path`
        
    - `X-Auth-Subject`
        
    - `X-Auth-Audience`
        
    - `X-Auth-Scopes`（可选）
        
    - `X-Ctx-*` / `X-Biz-*`（可选）
        

Body：

- 可为空（推荐为空，减少负载），AuthZ 不依赖 body 解析。
    

#### 6.1.3 Response（与 Envoy ext_authz HTTP 模式兼容）

- Allow：返回 200
    
    - 可选：在 200 Response Header 中返回 “需要注入到 upstream 的 header mutations”（例如增加/覆盖某些 `X-Biz-*`），具体 header 名与策略在 DEP-ENV 固化。
        
- Deny：返回 403
    
    - 可选：返回 JSON 错误体（用于审计/诊断；页面与 API 的最终呈现由 Envoy 统一策略决定）
        

#### 6.1.4 Fail-Closed

- 受保护路由上，AuthZ 超时/5xx 按 deny 处理（fail-closed），超时阈值默认 100ms（PLAN-001）。
    

---

## 7. 统一安全点（必须）

- GrantTicket 一次性：Exchange 必须 GETDEL/Lua 原子核销，禁止重复兑换
    
- EntryCode 一次性：Gate 必须 Lua GET+DEL 原子核销，防并发双花/重放
    
- URL query 不可信：资源绑定与业务读取必须以 token ctx 与 Envoy 注入 header 为准
    
- 外部 header 防伪造：入口必须 strip `X-Auth-* / X-Biz-* / X-Ctx-*` 再重注入
    

---

## 8. 备注 / Open Questions

- 本文已选定 AuthZ 输入载体为 A（只读 Envoy 注入头）。DEP-ENV-001 需固化：
    
    - ext_authz 目标 cluster
        
    - 受保护路由清单
        
    - `X-Authz-Method / X-Authz-Path` 的注入方式（request_headers_to_add）
        
    - allow/deny 时 header mutations 与错误呈现策略