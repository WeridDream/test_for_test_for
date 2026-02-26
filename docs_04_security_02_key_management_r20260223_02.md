# SEC-003 Key Management (SoftHSM2/PKCS#11 + JWKS Rotation)（SoT）  
- Doc ID: SEC-003  
- Status: FINAL  
- Owner: IU  
- Last Updated: 2026-02-23  
- Depends On: ARCH-001, PLAN-001, SEC-002, JWT-001, API-001, DDL-001  
- Logical Path: docs/04_security/02_key_management.md  
- Revision: r20260223_02  
- Supersedes:  r20260223_01 
  
---

## 1. 目标与范围  

### 1.1 目标  
- 将 JWT 签名私钥从应用代码与磁盘文件中彻底隔离，落在 **SoftHSM2（PKCS#11）** 的签名域中，私钥不出 HSM。  
- 固化 **kid/JWKS/轮换/GRACE 窗口/吊销** 的全生命周期规则，确保 Envoy 侧验签稳定。  
- 给出可落地的部署/权限/运维 Runbook 要点，避免“能跑但不可运维”。  
  
### 1.2 范围  
- Rust Issuer：唯一签名者（持有 PKCS#11 访问能力）  
- SoftHSM2：私钥存储与签名操作  
- sys_key_metadata：仅存公钥元数据（供管理台展示与 JWKS 输出）  
- Envoy：通过内部 mTLS 拉取 JWKS 并缓存（cache_duration=300s）  
- 轮换/吊销/应急流程：定时轮换 + 紧急撤销  
  

不覆盖：物理 HSM（但设计需保持可平滑迁移）。  

---

## 2. 威胁与安全原则（硬约束）  
- 私钥不落库、不出进程、不写日志、不进入配置仓库。  
- Go Exchange/Gate/AuthZ **不持有签名私钥**，也不执行签名。  
- JWKS 端点为**内部 mTLS 接口**，只允许 Envoy Workload 拉取（SEC-002）。  
- Key 轮换必须有 **GRACE 窗口**，保证旧 token 在 TTL 内可验，避免切换瞬时全站 401。  
- PIN/Token 目录权限为第一等安全边界（本机攻击面重点）。  
  
---

## 3. 加密与算法选型  

### 3.1 签名算法  
- JWT Header：`alg=EdDSA`（Ed25519）  
- Key 类型：OKP/Ed25519  
- 说明：Ed25519 适合高频验签（Envoy 本地），签名开销稳定。  
  
### 3.2 SoftHSM2 机制兼容性（必须预检）  
不同发行版/编译选项下 SoftHSM2 对 Ed25519/CKM_EDDSA 支持可能存在差异。  
- 必须在目标运行环境执行机制枚举预检（见第 10 章 Runbook）。  
- 若机制不支持：必须走 CHG（可选替代：迁移到支持 EdDSA 的 HSM/SoftHSM 构建，或改用 ECDSA P-256；默认不在本版本内变更）。  
  
---

## 4. key/kid/JWKS 数据模型与状态机  

### 4.1 DB 表对齐  
- 公钥元数据：`auth_center.sys_key_metadata`  
  - `kid`（PK）  
  - `alg` = `EdDSA`  
  - `public_key`（建议存 base64url，直接对应 JWKS `x`）  
  - `status` = `ACTIVE | GRACE | REVOKED`  
  - `expires_at`（UTC）  
  
> 禁止：DB 中出现私钥、PIN、SoftHSM2 token 路径等敏感信息。  

### 4.2 状态机定义（硬约束）  
- **ACTIVE**：用于签发新 token；也允许验签（Envoy 通过 JWKS）。  
- **GRACE**：不再签发新 token，仅用于验签（保证旧 token 在其 TTL 内仍可验）。  
- **REVOKED**：验签也应拒绝（仅用于应急吊销/事故处置）；一般情况下不轻易进入该态。  
  
### 4.3 kid 命名规则（建议固定）  
- 推荐：`kid_<yyyyMMdd>_<seq>`（如 `kid_20260223_01`）  
- 要求：  
  - 全局唯一  
  - 可读（便于审计）  
  - 不包含环境/域名/IP  
  
---

## 5. 轮换策略（Rotation）  

### 5.1 关键时间窗口（以秒为单位）  
定义：  
- `T_token_max`：该 aud/policy 最大 token TTL（来自 sys_auth_policy.max_ttl_sec，若多 aud 取最大值）  
- `T_skew`：时钟容忍（JWT-001：60s）  
- `T_jwks_cache`：Envoy JWKS 缓存（默认 300s）  
- `T_safety`：安全裕量（建议 60s）  
  

则 GRACE 窗口最小建议为：  
- `T_grace_min = T_token_max + T_skew + T_jwks_cache + T_safety`  
  
> 解释：保证“最后一张用旧 kid 签发的 token”在其 exp 前，Envoy 仍能拿到旧公钥验签。  

### 5.2 轮换流程（定时轮换）  
1) **生成新 keypair**  
   - 在 SoftHSM2 token 内生成 Ed25519 keypair（私钥留在 token 内）  
2) **注册新 key 为 ACTIVE**  
   - 在 `sys_key_metadata` 插入新 `kid`，status=ACTIVE，expires_at=未来轮换点  
3) **旧 key 从 ACTIVE → GRACE**  
   - 将上一把 ACTIVE key 更新为 GRACE（不再签发）  
4) **等待 GRACE 窗口结束**  
   - 达到 `T_grace_min` 后，可将 GRACE key 继续保持或转为 REVOKED（建议：自然过期场景保持 GRACE 到期再清理；事故吊销才 REVOKED）  
5) **可选清理**  
   - DB：标记或归档过期 key  
   - HSM：是否删除旧私钥对象取决于合规要求（默认不强制删除；若删除需 runbook 严格执行）  

### 5.3 紧急撤销（Emergency Revoke）  
触发条件：疑似私钥泄露、签名被滥用、重大安全事故。  
- 立刻将该 `kid` 标记为 `REVOKED`  
- JWKS 输出中仍可保留该 key（但 status=REVOKED 时 Envoy/业务应拒绝，具体实现以 DEP-ENV/代码为准）  
- 必须同时：  
  - 生成新 key → ACTIVE  
  - 重新签发后续 token  
  - 执行事故审计（记录原因与影响范围）  
  
> 注意：REVOKED 会使所有未过期 token 立即失效，属于“断臂求生”动作。  

---

## 6. JWKS 输出规范（Issuer 内部端点）  

### 6.1 端点  
- `GET /.well-known/jwks.json`（内部 mTLS，仅 Envoy allowlist）  
  
### 6.2 输出规则  
- 仅输出 `status in (ACTIVE, GRACE)` 的公钥  
- 输出字段：  
  - `kty=OKP`  
  - `crv=Ed25519`  
  - `alg=EdDSA`  
  - `use=sig`  
  - `kid=<kid>`  
  - `x=<base64url public key>`  
  

示例：  
```json  
{  
  "keys": [  
    { "kty":"OKP","crv":"Ed25519","kid":"kid_20260223_01","use":"sig","alg":"EdDSA","x":"BASE64URL_PUBLIC_KEY" }  
  ]  
}

```

---

## 7. Rust Issuer 与 PKCS#11 的工程约束

### 7.1 连接与会话管理（必须）

- Issuer 必须实现 **PKCS#11 session 池化**（固定上限），避免每请求创建/销毁 session 引发抖动与资源耗尽。
  
- 建议：
  
    - pool size：根据 CPU 核数与 QPS 评估（先从 8~32 起步）
      
    - session borrow 超时：短（例如 50ms），避免排队雪崩
      
    - 签名操作超时：短（例如 50~100ms），失败快速暴露并告警
      

### 7.2 Key 对象定位

- 通过 `kid -> pkcs11 key handle` 的映射定位私钥对象。
  
- 映射存储位置：
  
    - 不落 DB（避免泄露内部对象句柄）
      
    - 可在 Issuer 内存缓存（重启后可通过 label/kid 再查找）
      

### 7.3 日志与审计（必须）

- 禁止打印：PIN、token 路径、私钥对象属性、原始 JWT
  
- 必须打印（审计字段）：
  
    - request_id/trace_id
      
    - caller_spiffe_id、client_id
      
    - target_aud、kid、decision、reason
      
    - hsm_sign_latency_ms、hsm_error_code（脱敏）
      

---

## 8. SoftHSM2 部署与权限（非 k8s）

### 8.1 文件与目录

- SoftHSM2 token 目录（示例）：`/var/lib/softhsm/tokens`
  
- 配置文件（示例）：`/etc/softhsm2.conf`
  
- 运行用户：为 Issuer 创建独立 Unix 用户（如 `issuer`）
  

权限硬约束：

- token 目录：`chmod 0700`，owner=issuer
  
- 配置文件：`chmod 0640`，owner=root，group=issuer（或同等最小权限）
  
- 禁止将 token 目录打进镜像层；必须作为 host volume 持久化挂载。
  
- 生产环境以 **Issuer 自动 KeyGen + 写 sys_key_metadata** 为准；以下 CLI 仅用于机制验证/应急操作。不同工具/版本对 Ed25519 参数名可能不一致（如 `edwards25519` vs `ed25519`）。

### 8.2 PIN 管理

- SO-PIN 与 User PIN：
  
    - 不入库、不写代码、不写仓库
      
    - 通过系统安全机制注入：`systemd EnvironmentFile` / `docker secrets` / 受控配置目录
    
- PIN 轮换：
  
    - 必须走运维 SOP（Runbook），并与 Issuer 重启/热加载策略配套
      
    - PIN 轮换后必须验证签名可用与 JWKS 一致性
      

---

## 9. 与控制面（auth_center）的一致性要求

### 9.1 sys_key_metadata 写入规则（Issuer 负责）

- 新 key 生成后：
  
    - 将公钥写入 `sys_key_metadata`（public_key 为 base64url）
      
    - 设置 `status=ACTIVE`，并写入 `expires_at`
    
- 轮换时：
  
    - 将旧 ACTIVE 更新为 GRACE（只验签）
      
    - 应急撤销：更新为 REVOKED
      

### 9.2 读路径（Envoy）

- Envoy 不读 DB，只通过内部 mTLS JWKS 拉取公钥并缓存（cache_duration=300s）。
  

---

## 10. 运维 Runbook（最小可执行）

> 以下命令仅作为 SOP 骨架；具体路径按你们服务器标准化。

### 10.1 安装与机制预检（Debian/Ubuntu 示例）

sudo apt-get update  
sudo apt-get install -y softhsm2 opensc  

# 查看 SoftHSM2 模块路径（不同发行版可能不同）  
ls -l /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null || true  

# 枚举支持机制（必须确认存在 EdDSA/Ed25519 相关机制）  
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -M | egrep -i 'EDDSA|ED25519|EC_EDWARDS' || true

### 10.2 初始化 token（示例）

export SOFTHSM2_CONF=/etc/softhsm2.conf  
softhsm2-util --show-slots  

# 初始化 slot（示例：slot 0）  
softhsm2-util --init-token --slot 0 --label "RustIssuer" --so-pin <SO_PIN> --pin <USER_PIN>

### 10.3 生成 keypair（示例）生产环境以 **Issuer 自动 Keygen + 写 sys_key_metadata** 为准；以下 CLI 仅用于机制验证/应急操作。不同工具/版本对 Ed25519 参数名可能不一致（如 `edwards25519` vs `ed25519`）。

# 使用 pkcs11-tool 生成（示例参数，具体机制依发行版）  
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \  
  --login --pin <USER_PIN> \  
  --keypairgen --key-type EC:edwards25519 \  
  --label "kid_20260223_01" --id 01

### 10.4 验证公钥可导出（仅公钥）

pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \  
  --login --pin <USER_PIN> \  
  --read-object --type pubkey --label "kid_20260223_01" --output-file pubkey.der

### 10.5 Issuer 启动检查清单（必须）

- HSM 可登录、能完成一次签名（健康检查）
  
- JWKS 端点可被 Envoy 通过 mTLS 拉取（返回包含 ACTIVE/GRACE keys）
  
- sys_key_metadata 中 kid/status/expires_at 正确
  
- Envoy jwt_authn 验签成功率正常（无大量 jwks fetch error）
  

---

## 11. 验收口径（SEC-003）

- 私钥不落 DB、不落配置、不出 HSM；Go 不持私钥
  
- 轮换过程不产生全站 401：GRACE 窗口计算正确，JWKS 缓存与 TTL 考虑完整
  
- JWKS 仅内部 mTLS 可访问，且只输出 ACTIVE/GRACE keys
  
- Issuer 实现 session 池化与超时保护；HSM 故障可快速暴露并告警
  
- 应急撤销流程可执行、可审计（记录 kid、原因、影响范围）