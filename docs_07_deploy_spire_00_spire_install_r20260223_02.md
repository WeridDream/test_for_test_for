# DEP-SPIRE-001 SPIRE (Server/Agent/Entries) Non-K8s Deploy（SoT）  
- Doc ID: DEP-SPIRE-001  
- Status: FINAL  
- Owner: IU  
- Last Updated: 2026-02-24  
- Depends On: SEC-002, DDL-001  
- Logical Path: docs/07_deploy/spire/00_spire_install.md  
- Revision: r20260223_02  
- Supersedes: r20260223_01  
  
---  
  
## 1. 版本与目标  
  
- SPIRE: v1.14.1  
- 目标：  
  - 每台机器运行 1 个 spire-agent  
  - 1 台（先单点）运行 spire-server  
  - Workload 通过 UDS 获取 SVID  
  - Envoy 通过 SDS（同 UDS）获取证书与信任包  
  
---  
  
## 2. 目录与约定（建议）  
  
- 安装目录：`/opt/spire`  
- 数据目录：  
  - server: `/var/lib/spire/server`  
  - agent:  `/var/lib/spire/agent`  
- socket（建议使用 /run，避免 /tmp 清理）：  
  - agent UDS: `/run/spire/sockets/agent.sock`  
- 运行用户：  
  - server: `spire`  
  - agent:  `spire`  
  
---  
  
## 3. spire-server.conf（模板）  
  
> SPIRE Server 配置项与 plugins 块为官方参考结构（HCL/JSON 均可）:contentReference[oaicite:8]{index=8}  
  
```hcl  
server {  
  bind_address = "0.0.0.0"  
  bind_port    = "8081"  
  
  socket_path = "/tmp/spire-server/private/api.sock"
  
  trust_domain = "xjiot.link"  
  
  data_dir     = "/var/lib/spire/server"  
  log_level    = "INFO"  
  
  # 默认 X509-SVID TTL（可按需调整）  
  default_x509_svid_ttl = "1h"  
}  
  
plugins {  
  DataStore "sql" {
	plugin_data {  
		database_type = "sqlite3"  
		connection_string = "/var/lib/spire/server/datastore.sqlite3"  
	}  
}	


  NodeAttestor "join_token" {  
    plugin_data {}  
  }  
  
  KeyManager "disk" {  
    plugin_data {  
      keys_path = "/var/lib/spire/server/keys.json"  
    }  
  }  
}

```

## 4. spire-agent.conf（模板）

> Agent 配置参考（含 socket_path 用于 Workload API/Envoy SDS）

```
agent {  
  data_dir     = "/var/lib/spire/agent"  
  log_level    = "INFO"  
  
  trust_domain = "xjiot.link"  
  
  server_address = "10.0.0.10"   # <SPIRE_SERVER_IP>  
  server_port    = "8081"  
  
  # Workload API socket（同时作为 Envoy SDS UDS）  
  socket_path = "/run/spire/sockets/agent.sock"  
}  
  
plugins {  
  NodeAttestor "join_token" {  
    plugin_data {}  
  }  
  
  KeyManager "disk" {  
    plugin_data {  
      private_key_path = "/var/lib/spire/agent/agent.key"  
    }  
  }  
  
  WorkloadAttestor "unix" {  
    plugin_data {  
      discover_workload_path = true  
    }  
  }  
}

```

---

## 5. Join Token 启动流程（非 k8s）

### 5.1 Server 生成 join token（每台 agent 一枚）

/opt/spire/bin/spire-server token generate \  
  -socketPath /tmp/spire-server/private/api.sock \  
  -spiffeID spiffe://xjiot.link/ns/spire/sa/agent-node-01 \  
  -ttl 600

### 5.2 Agent 启动时使用 join token

/opt/spire/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf -joinToken "<JOIN_TOKEN>"

---

## 6. Workload Entries（非 k8s，用 unix selector 绑定）

### 6.1 绑定原则（硬约束）

- 每个服务使用独立 unix 用户运行（例如：`envoy`, `issuer`, `goauthz`, `gogate`, `formplat`, `jeecg`）
    
- entry selector 至少包含：
    
    - `unix:uid:<uid>`
        
    - `unix:path:<absolute_binary_path>`（强烈建议，降低同 uid 冒充）
        

### 6.2 entries.sh（模板）

```bash
#!/usr/bin/env bash  
set -euo pipefail  
  
SERVER_SOCKET="/tmp/spire-server/private/api.sock"  
TD="xjiot.link"  
PARENT_ID="spiffe://${TD}/ns/spire/sa/agent-node-01"   # 每台机器不同  
  
create_entry() {  
  local spiffe_id="$1"  
  local uid="$2"  
  local path="$3"  
  /opt/spire/bin/spire-server entry create \  
    -socketPath "${SERVER_SOCKET}" \  
    -parentID "${PARENT_ID}" \  
    -spiffeID "${spiffe_id}" \  
    -selector "unix:uid:${uid}" \  
    -selector "unix:path:${path}" \  
    -ttl 3600  
} 

  
# Envoy Gateway  
create_entry "spiffe://${TD}/ns/prod/sa/envoy-gateway" 2001 "/usr/local/bin/envoy"  
  
# Rust Issuer  
create_entry "spiffe://${TD}/ns/prod/sa/rust-issuer" 2002 "/opt/auth/rust-issuer"  
  
# Go AuthZ  
create_entry "spiffe://${TD}/ns/prod/sa/go-authz" 2003 "/opt/auth/go-authz"  
  
# Go Gate/Exchange  
create_entry "spiffe://${TD}/ns/prod/sa/go-gate" 2004 "/opt/auth/go-gate"  
  
# Form Platform (webhook sender) - 若表单平台也部署 agent  
create_entry "spiffe://${TD}/ns/prod/sa/form-platform" 2005 "/opt/form-platform/bin/form-platform"  
  
# JeecgBoot  
create_entry "spiffe://${TD}/ns/prod/sa/jeecg-boot" 2006 "/usr/bin/java"
``` 
---

## 7. 验收口径（DEP-SPIRE-001）

- agent 与 server 成功完成 attestation（join token）
    
- 任一 workload 可通过 `/run/spire/sockets/agent.sock` 获取 SVID（watch/healthcheck）
    
- Envoy 能通过 SDS 从同 UDS 获取：
    
    - tls cert secret（name = Envoy SPIFFE ID）
        
    - validation context secret（name = trust domain SPIFFE ID）
        
- 内部 mTLS allowlist 生效：SPIFFE 不在 allowlist 的调用必须 403