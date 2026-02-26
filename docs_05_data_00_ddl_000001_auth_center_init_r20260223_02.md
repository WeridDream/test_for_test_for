# DDL-001 auth_center Schema Definition（SoT）
- Doc ID: DDL-001
- Status: FINAL
- Owner: IU
- Last Updated: 2026-02-23
- Depends On: ARCH-001, FL-001, JWT-001, API-001
- Logical Path: docs/05_data/00_ddl/000001_auth_center_init.md
- Revision: r20260223_02
- Supersedes: r20260223_01

---

## 1. 目标与范围

### 1.1 目标
定义认证中台 Control Plane 的最小可用数据库结构（auth_center），支撑：
- 内部 mTLS + SPIFFE allowlist（client_identity）
- client / policy（aud、TTL、scopes、可选 ctx key 限制）
- subject rule（`subject{type,id} -> sub` 配置化生成）
- key metadata（仅公钥元数据，用于 JWKS 展示/拉取）
- blacklist（紧急封禁 user/jti；传播一致性由 OQ-003 继续细化）
- AuthZ 路由规则（method/path -> required scopes / binding rules）

### 1.2 非目标
- 不存储任何私钥/SoftHSM2 PIN（私钥域在 Rust Issuer + SoftHSM2）
- 不在 DB 层实现完整的 “scopes 解析/ctx schema 校验”（由服务层按 JWT-001/API-001 执行）

---

## 2. 全局约束与约定

### 2.1 数据库与时区
- MySQL 8.0+
- 全链路 UTC：脚本显式 `SET time_zone = '+00:00'`
- 字符集与排序：`utf8mb4` + `utf8mb4_0900_ai_ci`

### 2.2 软删除策略
- 统一用 `status`（ENABLED/DISABLED）做逻辑启停；不做物理删除（减少唯一键与历史恢复复杂度）。

### 2.3 与契约的一致性
- `client_id`：调用方逻辑 ID（对应控制面与审计）
- `spiffe_id`：SPIFFE URI SAN（allowlist）
- `target_aud`：Audience Registry 值（ARCH-001）
- `allowed_scopes` / `required_scopes`：空格分隔字符串（与 JWT-001 的 `scopes` 一致）
- `binding_rules_json`：用于 ext_authz 资源绑定（A 模式：AuthZ 只读 Envoy 注入头）

---

## 3. 表结构总览

| Table | 作用 | 关键字段 |
|---|---|---|
| `sys_auth_client` | 调用方主体（Client） | `client_id`, `status` |
| `sys_auth_client_identity` | SPIFFE allowlist（spiffe_id -> client_id） | `spiffe_id`, `client_id`, `status` |
| `sys_auth_policy` | client 对某 aud 的签发策略 | `client_id`, `target_aud`, `max_ttl_sec`, `allowed_scopes`, `ctx_key_allowlist_json` |
| `sys_auth_subject_rule` | sub 生成规则 | `client_id`, `subject_type`, `sub_template`, `id_pattern` |
| `sys_auth_route_rule` | AuthZ 路由/授权/绑定规则 | `target_aud`, `match_*`, `required_scopes`, `binding_rules_json` |
| `sys_key_metadata` | 公钥元数据（JWKS 展台） | `kid`, `public_key`, `status`, `expires_at` |
| `sys_token_blacklist` | 黑名单撤销 | `block_type`, `block_value`, `expire_at` |

---

## 4. 关键设计说明

### 4.1 为什么 `sys_auth_client_identity` 独立建表？
允许一个 `client_id` 同时绑定多个 `spiffe_id`（蓝绿/迁移/多实例），并能单独禁用某个身份而不影响整个 client。

### 4.2 为什么 policy 里 `allowed_scopes` 是字符串？
与 JWT-001 `scopes` 保持一致（空格分隔），便于比较与透传；复杂 scope 语义由 AuthZ 实现负责。

### 4.3 为什么 route rule 放在控制面？
因为你们选择 **A：AuthZ 只读 Envoy 注入头**，所以 AuthZ 要能在 DB/缓存里查到 “某 aud + path/method 需要什么 scopes/绑定规则”，减少业务侧硬编码。

### 4.4 blacklist 的清理策略
`expire_at` 用于数据老化：建议按小时/天清理过期行，避免表膨胀（实现放在 Runbook/运维任务）。

---

## 5. SQL（可执行脚本）

> 建议将下方 SQL 同步落盘为：
> - `docs/05_data/00_ddl/000001_auth_center_init.sql`（供 migrate 执行）
> - 本 md 作为可审阅 SoT

```sql
-- DDL-001 auth_center init
-- Status: FINAL
-- Revision: r20260223_01

SET time_zone = '+00:00';

CREATE DATABASE IF NOT EXISTS `auth_center`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

USE `auth_center`;

-- 1) Client：谁是调用方（逻辑主体）
CREATE TABLE IF NOT EXISTS `sys_auth_client` (
  `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT 'PK',
  `client_id` VARCHAR(64) NOT NULL COMMENT '逻辑调用方ID（如 jeecg-boot / biz-a / envoy-gateway）',
  `client_name` VARCHAR(128) NULL COMMENT '展示名',
  `status` TINYINT NOT NULL DEFAULT 1 COMMENT '1=ENABLED,0=DISABLED',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'UTC',
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_client_id` (`client_id`)
) ENGINE=InnoDB COMMENT='Control Plane：调用方（Client）';

-- 2) Client Identity：SPIFFE allowlist（spiffe_id -> client_id）
CREATE TABLE IF NOT EXISTS `sys_auth_client_identity` (
  `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT 'PK',
  `client_id` VARCHAR(64) NOT NULL COMMENT 'sys_auth_client.client_id',
  `spiffe_id` VARCHAR(255) NOT NULL COMMENT 'SPIFFE ID（URI SAN），用于内部 mTLS allowlist',
  `status` TINYINT NOT NULL DEFAULT 1 COMMENT '1=ENABLED,0=DISABLED',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'UTC',
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_spiffe_id` (`spiffe_id`),
  KEY `idx_client_id` (`client_id`),
  CONSTRAINT `fk_client_identity_client_id`
    FOREIGN KEY (`client_id`) REFERENCES `sys_auth_client` (`client_id`)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='Control Plane：Client SPIFFE allowlist';

-- 3) Policy：某 Client 允许申请哪些 aud、最大 TTL、允许 scopes、可选 ctx key 约束
CREATE TABLE IF NOT EXISTS `sys_auth_policy` (
  `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT 'PK',
  `client_id` VARCHAR(64) NOT NULL COMMENT 'sys_auth_client.client_id',
  `target_aud` VARCHAR(64) NOT NULL COMMENT '允许申请的 aud（Audience Registry 值）',
  `max_ttl_sec` INT NOT NULL DEFAULT 7200 COMMENT '该 client+aud 允许的最大 token TTL（秒）',
  `allowed_scopes` VARCHAR(512) NULL COMMENT '允许的 scopes（空格分隔）；NULL 表示不限制（由实现定义）',
  `ctx_key_allowlist_json` JSON NULL COMMENT '可选：进一步限制 ctx key（JSON array of strings），未配置则用 JWT-001 全局约束',
  `status` TINYINT NOT NULL DEFAULT 1 COMMENT '1=ENABLED,0=DISABLED',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'UTC',
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_client_aud` (`client_id`, `target_aud`),
  KEY `idx_aud` (`target_aud`),
  CONSTRAINT `fk_policy_client_id`
    FOREIGN KEY (`client_id`) REFERENCES `sys_auth_client` (`client_id`)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='Control Plane：签发策略（client -> aud/ttl/scopes/ctx约束）';

-- 4) Subject Rule：sub 生成规则（按 client_id + subject_type）
CREATE TABLE IF NOT EXISTS `sys_auth_subject_rule` (
  `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT 'PK',
  `client_id` VARCHAR(64) NOT NULL COMMENT 'sys_auth_client.client_id',
  `subject_type` VARCHAR(16) NOT NULL COMMENT 'user|service（与 API-001 subject.type 对齐）',
  `sub_template` VARCHAR(128) NOT NULL COMMENT 'sub 模板（例如 user:{id} / service:{id}）',
  `id_pattern` VARCHAR(128) NOT NULL DEFAULT '^[0-9A-Za-z_-]{1,64}$' COMMENT 'subject.id 校验正则（防畸形输入）',
  `max_id_len` INT NOT NULL DEFAULT 64 COMMENT 'subject.id 最大长度',
  `status` TINYINT NOT NULL DEFAULT 1 COMMENT '1=ENABLED,0=DISABLED',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'UTC',
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_client_subject_type` (`client_id`, `subject_type`),
  KEY `idx_subject_type` (`subject_type`),
  CONSTRAINT `fk_subject_rule_client_id`
    FOREIGN KEY (`client_id`) REFERENCES `sys_auth_client` (`client_id`)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='Control Plane：sub 生成规则（client+subject_type）';

-- 5) Route Rule：AuthZ 路由规则（aud+path+method -> scopes/bindings）
CREATE TABLE IF NOT EXISTS `sys_auth_route_rule` (
  `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT 'PK',
  `target_aud` VARCHAR(64) NOT NULL COMMENT '目标资源域 aud',
  `match_type` VARCHAR(16) NOT NULL DEFAULT 'PREFIX' COMMENT 'PREFIX|REGEX（MVP 推荐 PREFIX）',
  `match_value` VARCHAR(255) NOT NULL COMMENT '匹配值（prefix 或 regex）',
  `http_methods` VARCHAR(64) NULL COMMENT '允许方法（逗号分隔，如 GET,POST；NULL 表示任意）',
  `required_scopes` VARCHAR(512) NULL COMMENT '需要的 scopes（空格分隔；NULL/空表示不要求 scope）',
  `binding_rules_json` JSON NULL COMMENT '资源绑定规则（可选，JSON；用于 form_key/allowed_serial 等绑定）',
  `status` TINYINT NOT NULL DEFAULT 1 COMMENT '1=ENABLED,0=DISABLED',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'UTC',
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'UTC',
  PRIMARY KEY (`id`),
  KEY `idx_aud` (`target_aud`),
  KEY `idx_match` (`match_type`, `match_value`(64))
) ENGINE=InnoDB COMMENT='Control Plane：AuthZ 路由规则（aud+path+method -> scopes/bindings）';

-- 6) Key Metadata：只存公钥元数据（用于 JWKS / 管理台展示）
CREATE TABLE IF NOT EXISTS `sys_key_metadata` (
  `kid` VARCHAR(64) NOT NULL COMMENT 'Key ID（写入 JWT header.kid）',
  `alg` VARCHAR(16) NOT NULL DEFAULT 'EdDSA' COMMENT '算法（固定 EdDSA）',
  `public_key` TEXT NOT NULL COMMENT '公钥（建议存 base64url，与 JWKS.x 一致；不存私钥）',
  `status` ENUM('ACTIVE','GRACE','REVOKED') NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE=签发用;GRACE=仅验签;REVOKED=吊销',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'UTC',
  `expires_at` DATETIME NOT NULL COMMENT 'UTC：自然过期时间（轮换）',
  PRIMARY KEY (`kid`),
  KEY `idx_status_expires` (`status`, `expires_at`)
) ENGINE=InnoDB COMMENT='Control Plane：签名密钥元数据（公钥展台）';

-- 7) Blacklist：紧急撤销阀（传播一致性见 OQ-003）
CREATE TABLE IF NOT EXISTS `sys_token_blacklist` (
  `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT 'PK',
  `block_type` ENUM('USER','JTI') NOT NULL COMMENT '封禁维度：USER/JTI',
  `block_value` VARCHAR(128) NOT NULL COMMENT '被封禁的值（如 user:10086 或 jti UUID）',
  `reason` VARCHAR(255) NULL COMMENT '原因',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'UTC',
  `expire_at` DATETIME NOT NULL COMMENT 'UTC：数据清理时间线（通常=原 token exp）',
  PRIMARY KEY (`id`),
  KEY `idx_type_value` (`block_type`, `block_value`),
  KEY `idx_expire_at` (`expire_at`)
) ENGINE=InnoDB COMMENT='Control Plane：凭证黑名单（撤销）';