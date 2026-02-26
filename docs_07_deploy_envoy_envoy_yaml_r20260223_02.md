# DEP-ENV-001 Envoy Gateway Config（SoT）  
- Doc ID: DEP-ENV-001  
- Status: FINAL  
- Owner: IU  
- Last Updated: 2026-02-24  
- Depends On: FL-001, JWT-001, API-001, SEC-001, SEC-002, SEC-003, DDL-001  
- Logical Path: docs/07_deploy/envoy/envoy.yaml.md  
- Revision: r20260223_02  
- Supersedes: r20260223_01
  
---  
  
## 1. 目标与范围  
  
本配置定义“资源域网关（Resource Gateway）”的 **Envoy 单实例基线**，用于保护某一个 Audience（例如 `form_platform` / `biz_b_api` / `featured_doctor_api` 等）：  
  
- 外部入口：浏览器/WebView/APP → Envoy（不走 mTLS）  
- 网关职责：  
  1) jwt_authn：本地验签（EdDSA/Ed25519），JWT 来源 = Cookie 或 Bearer  
  2) Lua：强制 strip 外部伪造头（X-Auth*/X-Biz*/X-Ctx*），并从 JWT payload 注入可信头  
  3) ext_authz：将“只读注入头 + 原始 method/path”发给 Go AuthZ 做授权与资源绑定  
  4) router：转发到 upstream（表单平台/业务 API）  
  
- 内部调用（必须 mTLS + SPIFFE allowlist）：  
  - Envoy → Go AuthZ（/ext_authz/check）  
  - Envoy → Rust Issuer（JWKS：/.well-known/jwks.json）  
  
---  
  
## 2. 可替换参数（必须填）  
  
- `TRUST_DOMAIN`：例如 `xjiot.link`  
- `ENVOY_SPIFFE_ID`：例如 `spiffe://xjiot.link/ns/prod/sa/envoy-gateway`  
- `AUDIENCE`：本 Envoy 负责的资源域，例如 `form_platform`  
- `SPIRE_AGENT_UDS`：建议 `/run/spire/sockets/agent.sock`  
- `GO_AUTHZ_ADDR`：Go AuthZ 内网地址（host:port）  
- `RUST_ISSUER_ADDR`：Rust Issuer 内网地址（host:port）  
- `UPSTREAM_ADDR`：被保护上游（表单平台或业务服务）地址（host:port）  
- `GO_GATE_ADDR`：Go Gate/Exchange 地址（host:port）（用于 /_auth/*）  
  
---  
  
## 3. 不变量（硬约束）  
  
- 受保护路由：**fail-closed**（ext_authz 超时/5xx → 拒绝）  
- 外部请求头：一律不信任；必须 strip 再注入  
- JWT 只作为网关内部中间态；下游业务只读 Envoy 注入头（A 模式）  
- JWKS 仅内部 mTLS allowlist（只允许 Envoy）  
  
---  
  
## 4. envoy.yaml（基线配置）  
  
> 注意：这是“单 audience 网关”模板；若一个 Envoy 要保护多个 audience，需要复制 provider / vhost 或拆多个 Envoy 实例（推荐拆）。  
  
```yaml  
static_resources:  
  listeners:  
  - name: listener_http  
    address:  
      socket_address: { address: 0.0.0.0, port_value: 8080 }  
    filter_chains:  
    - filters:  
      - name: envoy.filters.network.http_connection_manager  
        typed_config:  
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager  
          stat_prefix: ingress_http  
          generate_request_id: true  
  
          access_log:  
          - name: envoy.access_loggers.stdout  
            typed_config:  
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog  
              log_format:  
                text_format: "[%START_TIME%] rid=%REQ(X-REQUEST-ID)% %REQ(:METHOD)% %REQ(:PATH)% %RESPONSE_CODE% %RESPONSE_FLAGS% %DURATION%ms\n"  
  
          route_config:  
            name: local_route  
            virtual_hosts:  
            - name: vhost_default  
              domains: ["*"]  
              routes:  
              # ---- 4.1 Public routes（不做 jwt/ext_authz） ----  
              - match: { prefix: "/_auth/" }  
                route: { cluster: go_gate_cluster }  
                typed_per_filter_config:  
                  envoy.filters.http.ext_authz:  
                    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute  
                    disabled: true  
  
              # ---- 4.2 Protected routes（必须 jwt + ext_authz）----  
              - match: { prefix: "/s/" }  
                route: { cluster: protected_upstream_cluster }  
              - match: { prefix: "/q/" }  
                route: { cluster: protected_upstream_cluster }  
              # 如需保护 API：再加 prefix（示例）  
              - match: { prefix: "/api/" }  
                route: { cluster: protected_upstream_cluster }  
  
              # ---- 4.3 default：拒绝（避免误放行）----  
              - match: { prefix: "/" }  
                direct_response:  
                  status: 404  
                  body:  
                    inline_string: "Not Found"  
  
          http_filters:  
          # 1) JWT authn（Cookie/Bearer）  
          - name: envoy.filters.http.jwt_authn  
            typed_config:  
              "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication  
              providers:  
                xjiot_provider:  
                  issuer: "xjiot-auth-center"  
                  audiences: ["form_platform"]   # <AUDIENCE>  
                  remote_jwks:  
                    http_uri:  
                      uri: "http://rust-issuer/.well-known/jwks.json"  
                      cluster: jwks_cluster  
                      timeout: 1s  
                    cache_duration: { seconds: 300 }  
                  from_headers:  
                  - name: Authorization  
                    value_prefix: "Bearer "  
                  from_cookies:  
                  - session_token  
                  payload_in_metadata: "jwt_payload"  
              rules:  
              - match:  
                  prefix: "/_auth/"  
                requires:  
                  allow_missing: {}  
              - match:  
                  prefix: "/"  
                requires:  
                  provider_name: "xjiot_provider"  
  
          # 2) Lua：strip 外部头 + 从 jwt_payload 注入可信头  
          - name: envoy.filters.http.lua  
            typed_config:  
              "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua  
              default_source_code:  
                inline_string: |  
                  local function starts_with(s, prefix)  
                    return string.sub(string.lower(s), 1, string.len(prefix)) == prefix  
                  end  
  
                  local function normalize_ctx_key(k)  
                    -- ctx key: snake_case or lower-kebab -> Header: X-Ctx-<Title-Kebab>  
                    -- 简化：仅做 '-' '_' 转换与首字母大写（足够稳定，业务侧不要依赖更复杂规则）  
                    k = string.gsub(k, "_", "-")  
                    return k  
                  end  
  
                  function envoy_on_request(request_handle)  
                    local h = request_handle:headers()  
  
                    -- 2.1 先收集需要删除的 header key（迭代时不能修改 header）  
                    local to_remove = {}  
                    for key, _ in pairs(h) do  
                      local lk = string.lower(key)  
                      if starts_with(lk, "x-auth-") or starts_with(lk, "x-biz-") or starts_with(lk, "x-ctx-") then  
                        table.insert(to_remove, key)  
                      end  
                    end  
                    for i=1,#to_remove do  
                      h:remove(to_remove[i])  
                    end  
  
                    -- 2.2 从 jwt_authn dynamic metadata 读 payload（payload_in_metadata）  
                    local md = request_handle:streamInfo():dynamicMetadata():get("envoy.filters.http.jwt_authn")  
                    if md == nil then  
                      return  
                    end  
  
                    -- 兼容不同 provider 的结构：取到 jwt_payload 节点  
                    local claims = nil  
                    if md["jwt_payload"] ~= nil then  
                      claims = md["jwt_payload"]  
                    else  
                      -- 若实现/版本导致嵌套结构变化，此处可按实际 metadata 形态调整  
                      claims = md  
                    end  
                    if claims == nil then  
                      return  
                    end  
  
                    -- 2.3 注入标准头（下游可信）  
                    if claims["sub"] ~= nil then h:add("X-Auth-Subject", tostring(claims["sub"])) end  
                    if claims["aud"] ~= nil then h:add("X-Auth-Audience", tostring(claims["aud"])) end  
                    if claims["jti"] ~= nil then h:add("X-Auth-JTI", tostring(claims["jti"])) end  
                    if claims["iss"] ~= nil then h:add("X-Auth-Issuer", tostring(claims["iss"])) end  
  
                    -- scopes：允许为空；统一透传为字符串  
                    if claims["scopes"] ~= nil then  
                      h:add("X-Auth-Scopes", tostring(claims["scopes"]))  
                    end  
  
                    -- 2.4 ctx 扁平化注入：X-Ctx-<key>  
                    local ctx = claims["ctx"]  
                    if type(ctx) == "table" then  
                      for k, v in pairs(ctx) do  
                        local hk = "X-Ctx-" .. normalize_ctx_key(tostring(k))  
                        h:add(hk, tostring(v))  
                      end  
                    end  
                  end  
  
          # 3) ext_authz（HTTP），fail-closed  
          - name: envoy.filters.http.ext_authz  
            typed_config:  
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz  
              http_service:  
                server_uri:  
                  uri: "http://go-authz/ext_authz/check"  
                  cluster: authz_cluster  
                  timeout: 0.10s  
                authorization_request:  
                  # 仅放行必要 headers 到 AuthZ（减少信息面）  
                  allowed_headers:  
                    patterns:  
                    - exact: "x-request-id"  
                    - exact: ":method"  
                    - exact: ":path"  
                    - exact: "host"  
                    - exact: "x-auth-subject"  
                    - exact: "x-auth-audience"  
                    - exact: "x-auth-scopes"  
                    - exact: "x-auth-jti"  
                    - exact: "x-auth-issuer"  
                    # ctx 白名单（示例，按你们 JWT-001 允许键补全）  
                    - prefix: "x-ctx-"  
                  headers_to_add:  
                  # 显式传递原始 method/path（便于 AuthZ 不依赖伪造头）  
                  - key: "X-Authz-Method"  
                    value: "%REQ(:METHOD)%"  
                  - key: "X-Authz-Path"  
                    value: "%REQ(:PATH)%"  
              failure_mode_allow: false  
              status_on_error:  
                code: 403  
              include_peer_certificate: true  
  
          - name: envoy.filters.http.router  
            typed_config:  
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router  
  
  clusters:  
  # 4.1 Go Gate / Exchange（公开路由，仅 /_auth/* 使用）  
  - name: go_gate_cluster  
    connect_timeout: 0.25s  
    type: STRICT_DNS  
    lb_policy: ROUND_ROBIN  
    load_assignment:  
      cluster_name: go_gate_cluster  
      endpoints:  
      - lb_endpoints:  
        - endpoint:  
            address:  
              socket_address: { address: go-gate, port_value: 16000 }  
  
  # 4.2 Protected upstream（表单平台或业务服务）  
  - name: protected_upstream_cluster  
    connect_timeout: 0.25s  
    type: STRICT_DNS  
    lb_policy: ROUND_ROBIN  
    load_assignment:  
      cluster_name: protected_upstream_cluster  
      endpoints:  
      - lb_endpoints:  
        - endpoint:  
            address:  
              socket_address: { address: upstream-service, port_value: 8081 }  
  
  # 4.3 SPIRE Agent SDS cluster（UDS）  
  - name: spire_agent  
    connect_timeout: 0.25s  
    type: STATIC  
    http2_protocol_options: {}  
    load_assignment:  
      cluster_name: spire_agent  
      endpoints:  
      - lb_endpoints:  
        - endpoint:  
            address:  
              pipe:  
                path: /run/spire/sockets/agent.sock  
  
  # 4.4 AuthZ cluster（Envoy -> Go AuthZ），mTLS via SPIRE SDS  
  - name: authz_cluster  
    connect_timeout: 0.25s  
    type: STRICT_DNS  
    lb_policy: ROUND_ROBIN  
    load_assignment:  
      cluster_name: authz_cluster  
      endpoints:  
      - lb_endpoints:  
        - endpoint:  
            address:  
              socket_address: { address: go-authz, port_value: 16105 }  
    transport_socket:  
      name: envoy.transport_sockets.tls  
      typed_config:  
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext  
        common_tls_context:  
          tls_certificate_sds_secret_configs:  
          - name: "spiffe://xjiot.link/ns/prod/sa/envoy-gateway"   # <ENVOY_SPIFFE_ID>  
            sds_config:  
              resource_api_version: V3  
              api_config_source:  
                api_type: GRPC  
                transport_api_version: V3  
                grpc_services:  
                - envoy_grpc:  
                    cluster_name: spire_agent  
          validation_context_sds_secret_config:  
            name: "spiffe://xjiot.link"  # <TRUST_DOMAIN SPIFFE ID>  
            sds_config:  
              resource_api_version: V3  
              api_config_source:  
                api_type: GRPC  
                transport_api_version: V3  
                grpc_services:  
                - envoy_grpc:  
                    cluster_name: spire_agent  
  
  # 4.5 JWKS cluster（Envoy -> Rust Issuer JWKS），mTLS via SPIRE SDS  
  - name: jwks_cluster  
    connect_timeout: 0.25s  
    type: STRICT_DNS  
    lb_policy: ROUND_ROBIN  
    load_assignment:  
      cluster_name: jwks_cluster  
      endpoints:  
      - lb_endpoints:  
        - endpoint:  
            address:  
              socket_address: { address: rust-issuer, port_value: 10903 }  
    transport_socket:  
      name: envoy.transport_sockets.tls  
      typed_config:  
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext  
        common_tls_context:  
          tls_certificate_sds_secret_configs:  
          - name: "spiffe://xjiot.link/ns/prod/sa/envoy-gateway"   # <ENVOY_SPIFFE_ID>  
            sds_config:  
              resource_api_version: V3  
              api_config_source:  
                api_type: GRPC  
                transport_api_version: V3  
                grpc_services:  
                - envoy_grpc:  
                    cluster_name: spire_agent  
          validation_context_sds_secret_config:  
            name: "spiffe://xjiot.link"  # <TRUST_DOMAIN SPIFFE ID>  
            sds_config:  
              resource_api_version: V3  
              api_config_source:  
                api_type: GRPC  
                transport_api_version: V3  
                grpc_services:  
                - envoy_grpc:  
                    cluster_name: spire_agent  
  
admin:  
  access_log_path: /tmp/envoy_admin_access.log  
  address:  
    socket_address: { address: 127.0.0.1, port_value: 9901 }


```
---
## 5. 验收口径（DEP-ENV-001）

- `/ _auth/*` 不需要 JWT，能正常 302 / 错误页返回
    
- 受保护路由（/s/ /q/ /api/）无 JWT 必须 401/403
    
- 外部伪造 `X-Auth-* / X-Ctx-*` 不影响授权结果（被 strip）
    
- Envoy 可通过 SPIRE SDS 取到自身 SVID，并成功 mTLS 访问：
    
    - Go AuthZ
        
    - Rust JWKS
        
- ext_authz 超时/失败：请求被拒绝（fail-closed）