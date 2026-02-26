# BG-001 业务背景与场景（SoT）
- Doc ID: BG-001  
- Status: FINAL  
- Owner: IU  
- Last Updated: 2026-02-23
- Depends On: docs/00_INDEX.md  
- Related Change Log: docs/09_records/decisions.md
- `Revision: r20260223_06`
- `Supersedes: r20260223_05`
---
## 1. 一句话目标
项目要解决的是不同业务场景下的认证体系问题，保证相关路径接口要经过认证才能进行调用，防止不明身份的人调用查看获取数据。需要产出一套完整高安全度的认证体系中间服务

---
## 2. 范围定义
### 2.1 In Scope
- 统一鉴权中台：票据签发/兑换/网关验签/身份透传
- 内部服务身份：SPIRE提供Workload Identity，用于内部mTLS
- 控制面（管理后台+DB）：对client/policy/subject规则/密钥元数据/黑名单进行配置化治理
- 覆盖业务场景：场景1~4 + webhook
### 2.2 Out of Scope
- **不重做业务服务自身账号体系**：本项目仅提供“门禁+身份透传”，不负责用户登录/认证
- 第三方表单平台默认**零侵入**（不修改其源码/权限体系）
---
## 3. 参与系统与职责边界
### 3.1 组件清单（高层）
- Edge Gateway：原生Envoy（jwt_authn本地验签；必要时ext_authz）
- Identity：SPIRE Server + Agent（Workload Identity/内部mTLS）
- Issuer：Rust（签名域/私钥域，内部接口）
- Exchange/Gate/AuthZ：Go（兑换、302gate、ext_authz授权判断）
- Control Plane：DB + 管理后台（独立前端）
- Cache：Redis（grant_ticket/entry_code映射与一次性消费；可选择黑名单加速）
- Third-Party Form Platform：表单平台（查询/填报页面）
- Biz System：业务平台、名医推荐等
### 3.2 关键职责边界
- Envoy：负责入口路由 + 本地验签；不把“业务账号体系”塞进网关
- SPIRE：仅用于**内部服务间mTLS 与身份**；公网浏览器访问不走SPIRE
- Rust Issuer：只负责签名与签发（受控mTLS调用）；不处理公网跳转与复杂web交互
- Go：负责兑换（grant_ticket->entry_code）、Gate（entry_code->Cookie+302）与ext_authz授权判断；不持有签名私钥
- 管理后台：负责配置化治理（client/policy/subject规则/公钥元数据/黑名单），不接管业务用户体系
---
## 4. 信任边界与mTLS边界

### 4.1 信任边界
- 公网用户/浏览器/WebView：不可信
- 内部服务：必须具备SPIFFE身份（SPIRE）才可以访问内部接口
- 私钥边界：签名私钥仅在Rust Issuer控制域内
### 4.2 mTLS强制范围
**必须mTLS + SPIFFE allowlist的内部接口**
- JeecgBoot/业务服务 -> Rust Issuer：issue_ticket
- JeecgBoot/业务服务 -> Go Exchange：exchange_entry_code（还有exchange_access_token）
- Envoy -> Go AuthZ：ext_authz/check（仅允许Envoy调用）
- 如（JWKS为内部端点）Envoy -> JKWS Provider内部拉取

**不使用mTLS的外部接口（浏览器访问，靠一次性码/Cookie/JWT）**
- Go Gate：`/_auth/gate?...`
- 表单平台页面与资源：`/s/*`、`/q/*`（由Envoy本地验签保护）
---
## 5. 主体模型
### 5.1 主体声明与生成规则
- 业务平台负责识别用户（账号体系仍在业务侧）
- 业务平台向认证中心声明主体使用结构化输入：
	- subject：{type:"user"|"service", id:"string类型"}
- 认证中心按控制面配置的subject规则生成最终JWT的sub：
	- 例：sub="user:id"或"service:client_id"
### 5.2 管理后台的"主体规则"能力边界
- 管理后台用于配置每个client的subject生成规则（模板/前缀/校验约束）
- 目标：避免在jeecgBoot/业务代码里硬编码sub规则
---
## 6. 凭证与会话载体（高层，字段细节放Contracts）
- GrantTicket：内部短票（仅服务到服务）
- EntryCode：一次性外部敲门码（URL载体，阅后即焚）
- SessionToken：HttpOnly Cookie中的JWT（页面后续请求复用）
- AccessToken：Authorization Bearer（API/服务间调用）
---
## 7. 业务场景
> 每个场景按：目标/入口/参与方/端到端步骤/校验点/成功条件/失败表现/审计点

### 7.1 场景1：第三方表单平台门禁（填报/查询）

- 目标：在不改变表单系统源码前提下，仅允许主业务系统授权的用户访问特定表单，并防止URL篡改和数据越权
- 入口：App内Web-view或PC端Iframe访问zxwj.xjiot.link/s/{formKey}或/q/{formKey}（/q/后续还有一个参数qid，qid是通过formKey能查询到的一个值，非固定值）
- 参与方：用户App、JeecgBoot（IdP）、Rust Issuer、Go Exchange、Envoy边缘网关、表单服务
- 步骤：
	1. 授权请求：用户点击填报，JeecgBoot校验本地Session后，通过mTLS调用Rust Issuer申请票据
	2. 票据签发：Rust从SoftHSM2获取签名，将formKey、correlationId、serialNumber锁定在JWT中并存入Redis，返回GrantTicket
	3. 换码重定向：Jeecg调Go Exchange将GrantTicket换为EntryCode，生成敲门URL
	4. 敲门种票：Web-view加载/_auth/gate?entry_code=...，Go服务原子核销entry_code并下发HttpOnly Cookie（SessionToken）
	5. 网关验签：浏览器302重定向至表单页，Envoy本地验签并注入X-Biz-Form-Key等Header传给表单后端
- 校验点：aud：form_platform、ctx.form_key一致性、ctx.correlation_id绑定、exp时效性
- 成功条件：用户看到正确表单页面且Cookie已安全注入
- 失败表现：EntryCode被重复使用报错（403）、表单Key不匹配报错（Envoy拦截）
- 审计点：trace_id（全链路追踪）、client_id：jeecg-boot、spiffe_id（mTLS验证信息）、decision：allow
### 7.2 场景2：业务A融合业务B（A->B）
- 目标：业务A需要调用业务B的受保护API（或跳转B的页面），实现免密互通，且A无法伪造B的身份。
- 入口：业务A后端API 或前端跳转链接
- 参与方：业务A服务、Rust Issuer、Go Exchange、Envoy（B侧网关）、（可选）Go AuthZ(ext_authz)、业务B服务
- 步骤：
  1. 获取票据：业务A后端凭自身 SPIFFE 身份向 Rust 申请针对 `aud=biz_b_api` 的 GrantTicket。
  2. 换取令牌：业务A调用 Go Exchange 用 GrantTicket 换取短寿命 AccessToken（JWT，TTL 见 FL-001）。
  3. 携带请求：业务A调用B（或重定向）时，请求头携带 `Authorization: Bearer <Token>`。
  4. 边缘验证：B侧 Envoy 拦截请求，本地验签（jwt_authn），校验 `aud == biz_b_api`，并按需要通过 ext_authz 校验 scopes/资源绑定；验证通过后注入清洗后的身份/上下文 Header 转发给业务B。
- 校验点：aud=biz_b_api、scopes（read/write）、issuer=xjiot-auth-center
- 成功条件：业务B收到带有 `X-Auth-Subject`（用户或服务主体）等可信注入头的请求并返回结果。
- 失败表现：JWT签名无效、aud 错误（越权调用）、scope 不足（403）
- 审计点：trace_id、client_id=biz-a、target_aud=biz_b_api、decision=allow/deny
### 7.3 场景3：名医推荐服务（无账号体系）
- 目标：名医推荐作为公共服务，不维护用户信息，但要求仅受信任的业务系统调用。
- 入口：内部 RPC 或 REST 调用 `/api/v1/recommend`（示例）
- 参与方：业务A服务、Rust Issuer、Go Exchange、Envoy（名医侧网关）、（可选）Go AuthZ(ext_authz)、名医推荐后端
- 步骤：
  1. M2M 身份：业务A使用 mTLS（SPIFFE）证明自己是受信调用方。
  2. 获取票据：业务A向 Rust 申请 `aud=featured_doctor_api` 的 GrantTicket（subject type=service）。
  3. 换取令牌：业务A向 Go Exchange 换取 AccessToken（JWT）。
  4. 透传调用：业务A携带 `Authorization: Bearer <Token>` 请求名医服务；Envoy 验签与授权后注入 `X-Auth-Subject` 等头并转发。
- 校验点：aud=featured_doctor_api、sub 类型为 service、exp 未过期、scope 满足路由要求
- 成功条件：名医推荐服务从注入头获取主体并记录审计，正常返回数据
- 失败表现：401 Unauthorized（缺 token/验签失败）、403 Forbidden（scope 不足）
- 审计点：trace_id、caller_spiffe_id、decision=allow/deny、reason
### 7.4 场景4：同业务 PC（Shiro）+ APP（Token）割裂
- 目标：废弃 APP 原有加密拦截器认证，将 APP 流量切入新架构；PC 端保留既有 Shiro 认证不受影响，并在后端实现身份标识统一。
- 入口：
  - APP：携带 `Authorization: Bearer <JWT>` 访问 API
  - PC：浏览器携带 Shiro session 调业务后端获取 AccessToken，再以 Bearer 访问 API（或在页面类场景走 Cookie）
- 参与方：JeecgBoot/业务后端（Token Broker）、Rust Issuer、Go Exchange、Envoy 网关、业务服务
- 步骤：
  1. Token Broker：用户在 PC 或 APP 完成业务侧登录后，由业务后端在服务端执行 `issue_ticket -> exchange_access_token`（aud=core_business_api），将 AccessToken 返回给前端（PC/APP）。
  2. 网关统管：Envoy 拦截业务请求，使用 jwt_authn 本地验签；必要时 ext_authz 校验 scope/资源绑定。
  3. 身份清洗：Envoy strip 外部伪造身份头后，注入 `X-Auth-Subject`（以及必要的 ctx/scopes）给业务服务。
  4. 业务侧用法：业务服务不再信任前端传 userId 参数，统一从 `X-Auth-Subject` 推导当前用户并查询。
- 校验点：JWT 签名有效、aud=core_business_api、exp 未过期、scope 满足路由要求
- 成功条件：后端业务代码不再读取前端传来的 userId 参数，统一从注入头获取主体身份
- 失败表现：token 伪造/过期/越权被 Envoy 拦截
- 审计点：trace_id、client_type=PC/APP、subject、decision=allow/deny
### 7.5 Webhook回调（表单平台->业务系统）
- 目标：实现表单平台数据推送的**来源防伪与数据去重**。确保只有经过认证的表单推送能进入业务A的接收接口，且不因重试导致重复入库。
- 入口：表单平台 POST 推送至业务A的 `/api/webhook/data`
- 参与方：表单平台、Envoy 网关、业务服务（接收方）、（可选）Redis、DB（幂等唯一约束）

- 步骤：
  1. 身份发起：表单平台作为 SPIRE Workload 获取 X.509-SVID，向 Envoy 发起 mTLS 请求。
  2. 身份鉴定（网关）：Envoy 校验 **mTLS 证书链 + SPIFFE ID（URI SAN）** 是否在 allowlist（如 `spiffe://.../sa/form_platform`）。
  3. 后端透传：Envoy **strip** 外部请求中所有伪造的 `X-Auth-* / X-Biz-* / X-Ctx-*`，并注入可信 caller identity（例如：`X-Auth-Service-Identity: form_platform` 或 `X-Caller-Spiffe-Id: ...`），再转发至业务A。
  4. 幂等判定：业务A提取 `correlation_id` 与 `form_key`，以 **(correlation_id, form_key)** 作为幂等唯一键做去重（强一致建议落 DB 唯一约束；Redis SETNX 可作为性能加速但不是 SoT）。
  5. 业务闭环：业务A按既有实现落库（Receipt + Outbox 同事务）并返回 200；若重复投递命中幂等，仍返回 200（静默成功）。

- 认证：
  - 核心：Envoy 对回调请求进行 **mTLS + SPIFFE allowlist** 校验（Webhook 不纳入票据体系，不使用 AccessToken/EntryCode）。
  - 补充：业务A仅信任 Envoy 注入的 caller identity header（且前提是 Envoy 已 strip 外部同名 header）。

- 幂等：以 **(correlation_id, form_key)** 为幂等键；重复投递返回 200。
- 校验点：mTLS/SPIFFE 通过；caller identity header 来自 Envoy 注入；幂等键未重复（或重复则 200）。
- 成功条件：业务A成功接收到一条合法且不重复的表单数据，并正确入库/入队。
- 失败表现：非法推送被 Envoy 拒绝；重复推送在业务A侧静默幂等成功。
- 审计点：trace_id、caller_spiffe_id、form_key、correlation_id、serial_number、form_key、correlation_id、serial_number、action：WEBHOOK_RECEIVED
---
## 8. 通用性与扩展推演
### 8.1待推演"未知场景清单"
- iframe SameSite属性兼容性：Chrome 80+ 对跨站Cookie的限制，需验证SameSite=None；Secure在web-view与不同浏览器内核中的表现，防止重定向后Cookie丢失
- 多租户tenant_id隔离：未来如果引入多机构，验证ctx中携带tenant_id在Envoy层的路由分发逻辑（基于Header路由到不同数据库示例）
- 离线填报与异步同步：App在断网状态下缓存的表单数据，在恢复网络后批量上报时的Token时效性（exp）与补发逻辑（这一点，我认为是不是可以考虑离线填报的数据人工导入避免这个问题？）
### 8.2 表单平台深度改造后选清单
- 上下文渲染感知
	- 原因：希望表单能自动填充X-Biz-Correlation-Id对应的业务信息
	- 影响：改造前端JS
	- 替代方案：表单平台增加一个Hook，从Envoy注入的可信Header中提取信息并映射到表单字段
---
## 9. 非功能目标（NFR）
- 性能目标：
	- 网关验证延迟：Envoy本地Ed25519验签P99 < 1ms
	- 签发吞吐量：Rust Issuer（SoftHSM2）单示例QPS目标 > 5000（受限于HSM签名速度）
	- 并发处理：Go Exchange状态转换请求P95 < 5ms（Redis内存操作）
- 可用性：
	- 系统SLA：99.99%
	- 降级策略：若后端Redis挂死，Go Verify切换为"纯签名校验模式"，放弃黑名单检查，优先保证大部分用户进得去（可能是一个风险点）
	- 公钥缓存：Envoy本都缓存JWKS 5分钟，即便Go Auth故障，存量Token依然可以正常访问
- 安全指标：
	- 零信任假设：假设内网流量被完全监听，所有凭证必须经过Ed25519非对称加密，私钥永不离HSM
	- 紧急禁用目标：通过管理面禁用某个ClientID或UserID，全网生效延迟目标< 2秒（基于Redis Pub/Sub 广播或快速轮询）
- 可观测性：
	- 最小审计字段：trace_id，client_id，spiffe_id，subject，action，target_aud，result_code，latency_ms
---
## 10. 未决项
- OQ-003：黑名单传播一致性
	- 描述：当有多个Envoy节点部署时，如何确保黑名单更新一致性
	- 定型建议：采用Go Auth推送至Redis，各个网关节点或Verify服务通过长轮询/Pub-Sub订阅。目标：最大同步时差不超过1秒
---
## 11. 关联文档
- FL-001：端到端流程
- ARCH-001：总体架构
- JWT-001：JWT Claims规范
- DDL-001：控制面DDL
- DEP-ENV-001：Envoy配置
- DEP-SPIRE-001：SPIRE配置
- CHG-LOG：decisions.md