# PLAN-001 设计与实施规划（SoT）
- Doc ID: PLAN-001
- Status: FINAL
- Owner: IU
- Last Updated: 2026-02-23
- Depends On: BG-001, FL-001, ARCH-001
- `Revision: r20260223_01`
---
## 1. 目标与非目标

### 1.1 目标
- 在不改动各业务账号体系的前提下，交付一套可复用的“门禁 + 身份透传”鉴权中台：
  - Envoy 入口：jwt_authn 本地验签 + ext_authz 授权与资源绑定
  - SPIRE：内部 Workload Identity（全内部接口 mTLS + SPIFFE allowlist）
  - Rust Issuer（SoftHSM2/PKCS#11）：签名域与 JWKS 发布
  - Go Exchange/Gate/AuthZ：兑换、统一错误页、授权判断
  - Control Plane：auth_center schema + Admin UI（React/Vite/Tailwind）
- 覆盖并验证 FL-001 场景1~4 + webhook 的端到端闭环与回归用例。
- 产出可审计、可观测、可回滚的部署与运维文档（DEP + Runbooks）。

### 1.2 非目标
- 不实现/不替换业务系统的登录、SSO、账号体系与用户管理。
- 不对第三方表单平台做深度改造（如需改造必须走变更单）。
---
## 2. 里程碑与冻结点（SoT 驱动）

### M1：契约冻结（Contracts Freeze）
- 输出并冻结：
  - JWT-001：claims/scopes/ctx 约束（OQ-002 关闭）
  - API-001：Issuer/Exchange/Gate/AuthZ 接口定义（OpenAPI/JSON）
- 验收：所有字段名/语义与 FL-001/ARCH-001 无矛盾；后续实现不得擅自改字段。

### M2：DDL 冻结（Data Freeze）
- 输出并冻结：
  - DDL-001：auth_center schema（client/policy/subject_rule/key_metadata/blacklist）
- 验收：控制面字段与契约一致；管理后台可按 DDL 直接建模。

### M3：数据面闭环（Data Plane MVP）
- 交付：
  - Rust Issuer（SoftHSM2 签名 + JWKS 内部端点）
  - Go Exchange（grant_ticket->entry_code/access_token）
  - Go Gate（统一错误页 + 302 种 Cookie）
  - Go AuthZ（ext_authz）
  - Redis/配置与最小 runbook
- 验收：FL-001 场景1/2/3 通过（含重放/篡改/无票访问用例）。

### M4：网关落地（Envoy + SPIRE）
- 交付：
  - Envoy 配置：jwt_authn + ext_authz + header strip/inject + 错误页策略
  - SPIRE 配置：server/agent/entries（非 k8s）
- 验收：内部接口全 mTLS；页面跳错误页/API JSON；ext_authz fail-closed 生效。

### M5：控制面与运维（Control Plane & Ops）
- 交付：
  - Admin UI（最小可用：client/policy/subject_rule/key_metadata/blacklist）
  - 黑名单/禁用生效延迟目标（OQ-003 关闭或部分关闭）
- 验收：一键禁用 client 在目标延迟内生效；审计字段齐全。
> 设计约束：Admin UI 不做“临时 CRUD 面板”。M5 阶段需产出 UI/UX 规范（信息架构、关键页面原型、操作风险提示与审计可视化），并在实现前冻结为 SoT（UI-001），避免后期返工。

### M6：全场景回归与压测（Quality Gate）
- 交付：
  - 回归用例脚本（含 U-xxx 推演清单关键项）
  - 压测报告（QPS/P99、JWKS/SoftHSM2/Redis 瓶颈）
- 验收：满足 NFR（性能/可用性/可观测性）并形成最终发布清单。
---
## 3. 工作流与验收口径（Definition of Done）

### 3.1 SoT 驱动与冻结规则
- 所有变更必须先改 SoT，再改代码；冻结后修改必须走 CHG（Why/Impact/Diff/Rollback）。
- 冲突裁决优先级：DDL > Contracts > decisions.md > design/flows > deploy/runbooks。
- Uploaded File 不复用同名：每次修改上传新 revision（`..._rYYYYMMDD_nn`），并由 Index Registry 指向最新版本。

### 3.2 全局 DoD（适用于每个里程碑 M1~M6）
- SoT：对应文档已上传且 Index Registry 指向最新 revision；历史版本标记 deprecated/archived。
- 契约一致性：字段名/语义与 FL-001/ARCH-001 无漂移；至少提供 3 条端到端样例（正常/篡改/重放）。
- 安全：
  - 内部接口：mTLS（SPIRE）+ SPIFFE allowlist 生效；
  - 外部入口：无票访问被拒（401/403/错误页），并符合错误页/错误体策略。
- 可观测：最小审计字段齐全（至少包含：trace_id/request_id、client_id、caller_spiffe_id、aud、jti、decision、reason、latency）。
- 回归：每个场景至少 3 条可回归用例通过；覆盖统一失败矩阵（401/403/302错误页/5xx/可重试与否）。
- 运维：提供最小 runbook（启动/配置/排障/回滚），并能在预期环境复现。

### 3.3 生效延迟目标（硬性口径）
- Control Plane 策略变更、client 禁用、黑名单（user/jti）生效延迟目标：**< 10s**（以数据面缓存刷新/推送机制实现）。
- 若未达成：必须给出压测/观测数据与明确改进计划，作为阻塞项处理。

### 3.4 性能目标（Target, non-blocking in MVP）
- 性能目标：QPS 5,000（峰值 10,000），P99 < 10ms（网关验签路径）。
- 验收口径：MVP 阶段以“压测报告 + 瓶颈分析 + 明确改进计划”为硬要求；是否达成上述目标不作为阻塞验收条件。
---
## 4. 风险与缓解（Risk & Mitigation）

> 口径：本章只写“会影响可用性/安全性/一致性/可运维性”的真实风险，并给出可执行缓解策略与落点文档。

### R-001 SoftHSM2 可用性与性能（签名域风险）
- 风险：SoftHSM2 发生 slot/token 不可用、会话竞争（session contention）、签名延迟抖动，会直接影响 Issuer 发票与 key 轮换。
- 影响：签发不可用 → 全链路换票失败（场景1/2/3/4受影响）。
- 缓解：
  - Issuer 侧实现 PKCS#11 session 池化（固定上限，避免每请求新建 session）。
  - 引入签名超时与熔断（短超时+快速失败），避免堆积雪崩。
  - 关键指标：签名耗时、失败率、session 池耗尽次数。
  - 运行手册：SoftHSM2 token 目录备份/恢复流程、重启后 kid/公钥一致性验证。
- 落点：SEC-003（Key Management）、Runbooks（HSM 运维）

### R-002 JWKS 拉取与轮换窗口（kid/公钥一致性）
- 风险：Envoy 拉取 JWKS 失败、缓存过期、kid 切换期间旧 token 验签失败导致大面积 401。
- 影响：网关验签失败 → 页面/接口不可用。
- 缓解：
  - JWKS 仅内部 mTLS 拉取（防劫持），并设置合理 cache_duration。
  - Key 轮换采用 GRACE 窗口：新 kid 签发 + 旧 kid 继续可验（到旧 token 自然过期）。
  - 必须压测：轮换期间 P99 与错误率。
- 落点：SEC-003、DEP-ENV（Envoy 配置）、Runbooks（轮换流程）

### R-003 ctx 体积与 Header 注入上限（OQ-002）
- 风险：ctx 过大/嵌套导致 Envoy/Lua/ext_authz 注入 header 失败（431/请求被代理拒绝），或造成内存/CPU 抖动。
- 影响：合法请求被拒、网关资源消耗异常。
- 缓解：
  - JWT-001 冻结 ctx 约束：仅扁平键值对、禁止嵌套、总大小上限、key/value 长度上限。
  - ctx → Header 默认白名单透传（非白名单不注入）。
  - Issuer/Exchange 在入口做校验，超限直接 4xx 拒绝（不能把异常带进 Envoy）。
- 落点：JWT-001（关闭 OQ-002）

### R-004 黑名单/禁用传播一致性（OQ-003，目标 <10s）
- 风险：client 禁用、jti/user 黑名单传播延迟过大，导致事故爆炸半径扩大。
- 影响：安全响应不达标。
- 缓解：
  - 数据面本地缓存 + 定时刷新（≤10s），必要时支持“主动推送/通知”机制（后续细化）。
  - 关键指标：变更生效延迟分位数、各节点缓存版本号。
- 落点：SEC-001/PLAN（关闭 OQ-003）、Runbooks（应急禁用）

### R-005 ext_authz 故障导致可用性风险（fail-closed）
- 风险：受保护路由配置 fail-closed，authz 服务抖动/超时会造成 403/503 放大。
- 影响：局部/全站不可用（取决于保护路由覆盖面）。
- 缓解：
  - 明确“受保护路由”清单，非关键路由不接入 ext_authz。
  - ext_authz 设置短超时 + 明确错误策略（超时按 fail-closed），并配套健康检查与告警。
  - 可选：对“可容忍”路由使用本地规则（后续不在 MVP 强推）。
- 落点：DEP-ENV、Go AuthZ 实现、压测报告

### R-006 Cookie / WebView / iframe 的兼容性
- 风险：WebView/iframe 的 Cookie 策略差异导致门禁不稳定，尤其 cross-site iframe。
- 影响：场景1“能进页面”不稳定，用户体验差。
- 缓解：
  - same-site iframe：目标支持并覆盖回归用例；
  - cross-site iframe：不承诺稳定，提供降级路径（顶层跳转/新开页/同站代理为 first-party）。
  - 错误页必须可诊断（展示 request_id）。
- 落点：FL-001 U-002、DEP-ENV、前端接入说明

### R-007 绕过 Envoy（直连上游）破坏信任链
- 风险：如果上游服务端口可被直连，攻击者可绕过 jwt_authn/ext_authz 与 header strip/inject。
- 影响：鉴权形同虚设。
- 缓解：生产网络与进程监听策略强约束：
  - 上游服务仅监听内网/loopback；安全组/防火墙禁止公网直达；
  - 只暴露 Envoy 入口。
- 落点：DEP-ENV、Runbooks（网络检查清单）

### R-008 Redis 依赖风险（兑换/Gate 一次性核销）
- 风险：Redis 故障导致 grant_ticket/entry_code 无法核销，gate 无法种 cookie。
- 影响：场景1无法进入；场景2/3/4换票失败。
- 缓解：
  - Redis 高可用（至少主从/哨兵或等价方案），并对关键命令耗时/错误率告警。
  - 失败表现统一：gate 返回错误页（带 request_id），内部接口 503 可重试。
- 落点：DEP-REDIS、Runbooks、压测报告（瓶颈定位）
---
## 5. 测试与压测计划（Quality & Performance Plan）

### 5.1 功能回归（必须）
- 覆盖范围：FL-001 场景1~4 + Webhook（含 8 章 U-xxx 推演清单中的关键项）。
- 每个场景至少 3 条可回归用例：正常 / 篡改 / 重放。
- 错误呈现一致性：
  - 页面路由：401/403 → 302 `/_auth/error`（HTML，含 request_id）
  - API 路由：401/403 → JSON 错误体（含 request_id，不 302）
- Webhook：
  - mTLS+SPIFFE allowlist 拒绝非法来源
  - 幂等键（correlation_id + form_key）重复投递返回 200 且不重复入库

### 5.2 安全测试（必须）
- 内部接口：mTLS 必须生效（无证书/非 allowlist SPIFFE ID → 401/403）
- Header 防伪造：外部请求携带 `X-Auth-* / X-Biz-* / X-Ctx-*` 必须被 Envoy strip 并重注入
- 授权：aud/scope 不满足必须拒绝（401/403），且原因可审计
- 资源绑定：表单场景 formKey/serial 与 ctx 不一致必须拒绝（403）
- 绕过测试：验证上游服务无法绕过 Envoy 直连（网络/监听策略）

### 5.3 压测策略（两档：最小必做 + 最终冲高）

#### A) Smoke Load（必做，开发期轻量）
- 目的：验证链路在并发下稳定、不崩溃，并尽早暴露明显瓶颈（SoftHSM2/Redis/JWKS/ext_authz）。
- 环境：按实际部署的“最小拓扑”跑基线：
  - 1×Envoy（jwt_authn + ext_authz + 错误页策略）
  - 1×SPIRE server/agent（内部 mTLS）
  - Redis + Issuer/Exchange/AuthZ
- 负载：100~300 并发，持续 3~5 分钟（按实际资源可调）
- 产出：1 页结果（P95/P99、错误率、Top 3 瓶颈点与改进建议）

#### B) Target Load（M6 阶段，形成正式报告）
- 性能目标（Target, non-blocking）：QPS 5,000（峰值 10,000），P99 < 10ms（网关验签路径）。
- 验收口径：以“压测报告 + 瓶颈分析 + 明确改进计划”为硬要求；是否达成上述目标不作为阻塞验收条件。

### 5.4 工具与环境（建议）
- 压测工具：k6 OSS（自建运行，免费）
- 环境分层：
  - 本地最小闭环（docker compose）
  - 预发/联调环境（尽量贴近生产拓扑：Envoy + SPIRE + Redis + Issuer/Exchange/AuthZ）
---
## 6. 交付物清单（Deliverables）

> 交付物以 SoT 为准，代码/配置/运行手册必须能复现 FL-001 的端到端链路。

### 6.1 SoT 文档（必须）
- BG-001：业务背景与范围
- FL-001：端到端流程（含未知场景推演清单与统一失败矩阵）
- ARCH-001：总体目标架构
- PLAN-001：设计与实施规划（本文）
- decisions.md：关键决策与变更单（CHG 记录）
- 后续冻结文档（里程碑产出）：
  - JWT-001：JWT Claims / scopes / ctx 约束（关闭 OQ-002）
  - API-001：Issuer/Exchange/Gate/AuthZ API 契约（OpenAPI/JSON）
  - DDL-001：auth_center schema（控制面 DDL）
  - DEP-ENV-001：Envoy 配置（jwt_authn/ext_authz/strip+inject/错误页策略）
  - DEP-SPIRE-001：SPIRE 部署与 entries（非 k8s）
  - SEC-003：SoftHSM2/PKCS#11 key management 与轮换策略（含 Runbook）
  - RUN-001：运行手册（启动/排障/回滚/应急禁用）

### 6.2 后端服务（必须）
- Rust Issuer
  - 内部 mTLS（SPIRE）
  - SoftHSM2/PKCS#11 签名
  - 签发 GrantTicket
  - 提供 JWKS（内部端点，仅 Envoy 拉取）
- Go Exchange
  - 内部 mTLS（SPIRE）
  - 兑换：GrantTicket -> EntryCode / AccessToken
- Go Gate
  - 外部入口：`/_auth/gate`（EntryCode 一次性核销）
  - 种 Cookie（SessionToken）+ 302
  - 统一错误页：`/_auth/error`（含 request_id）
- Go AuthZ（ext_authz）
  - 内部 mTLS（SPIRE）
  - aud/scope/资源绑定判定（受保护路由 fail-closed）

### 6.3 网关与身份基础设施（必须）
- Envoy
  - jwt_authn：本地验签（Cookie/Bearer）
  - ext_authz：授权与资源绑定（fail-closed）
  - header strip/inject：`X-Auth-* / X-Biz-* / X-Ctx-*`
  - 页面路由错误页（302）与 API JSON 错误体策略
- SPIRE（非 k8s）
  - SPIRE Server/Agent 安装与配置
  - Workload entries：为 Issuer/Exchange/AuthZ/Envoy/业务平台/表单平台（如可）建立 SPIFFE 身份

### 6.4 控制面（M5 交付）
- 数据库：`auth_center` schema（DDL-001）
- Admin UI（React + Vite + Tailwind）
  - Client/Policy/Subject Rule/Key Metadata/Blacklist 最小闭环
  - UI/UX 规范冻结为 UI-001（信息架构、关键页面原型、操作风险提示、审计可视化）

### 6.5 配置与部署资产（必须）
- docker-compose（本地闭环）：Envoy + SPIRE + Redis + Issuer/Exchange/Gate/AuthZ
- 生产部署模板（非 k8s）：systemd/service 文件或等价启动脚本
- 环境变量/配置文件模板（含最小默认值与安全建议）
- 证书/密钥与 token 目录的备份/恢复说明（尤其 SoftHSM2）
- 部署主路径：Docker 镜像 + docker compose（生产/预发一致）；systemd 作为可选兜底（可用于拉起 compose 或直接拉起二进制）。
- 表单平台纳入 SPIRE：表单平台所在机器部署 SPIRE Agent，使 webhook 也统一走 mTLS + SPIFFE allowlist。

### 6.6 回归与压测资产（最小必做）
- 回归用例清单（对应 FL-001 场景用例）
- Smoke Load 脚本（k6 OSS，100~300 并发，3~5 分钟）与一页结果模板
- M6 阶段完整压测报告模板（吞吐/延迟/资源/瓶颈与改进计划）

### 6.7 观测与审计（必须）
- 最小审计字段落地（trace_id/request_id、client_id、caller_spiffe_id、aud、jti、decision、reason、latency）
- Envoy access log 与关键指标（jwt_authn/ext_authz/JWKS 拉取）
- Redis/SoftHSM2 关键指标与告警项（失败率、延迟、session 池耗尽）