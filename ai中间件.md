# AI Guard 中间件

> 返回 [README](README.md) | 参阅 [中间件](中间件.md) | [业务接入指南](业务接入指南.md) | [AI Guard 设计文档](ai-guard-design.md)

---

## 概述

AI Guard 是 Stew 网关内置的 AI 请求防护中间件，为接入的 AI / LLM 类服务提供统一的：

- Token 配额管理（每用户每窗口）
- 请求频率限制（每分钟）
- 输入内容审查（关键词黑名单 + 话题白名单）
- 意图分类（规则引擎 / LLM 分类器）
- 上下文截断（控制历史消息长度）
- 请求体解析（三层提取策略）
- 审计日志

运维团队通过全局配置启用 AI Guard，业务团队通过服务注册配置 + Proto 注解即可接入。

---

## 架构

AI Guard 采用**两阶段架构**，解决 hyper `Incoming` body 只能读取一次的限制：

```
                    Phase 1                              Phase 2
                (请求中间件)                          (代理层)
  +--------------------------+        +----------------------------------+
  | AiGuardMiddleware        |        | AiGuardBodyProcessor             |
  |                          |        |                                  |
  | - 检查 ai_guard_enabled  |        | - 读取完整请求体                 |
  | - 匹配 include_paths     |        | - 三层提取策略解析字段           |
  | - 提取 user_id / IP      |        | - Token 估算                     |
  | - 构建 PendingCheck      |        | - 关键词扫描 + 话题分类          |
  | - 存入 request.extensions|------->| - Redis 配额预检                 |
  | - 不读取 body            |        | - 上下文截断                     |
  +--------------------------+        | - 注入预算头                     |
                                      | - 输出审计事件                   |
                                      +----------------------------------+
```

### 在中间件链中的位置

```
请求方向：
  ... UnifiedAuth -> HttpToGrpcMetadata -> AiGuard(Phase1) -> Logging -> HybridProxy
                                                                              |
                                                                    AiGuardBodyProcessor(Phase2)
                                                                              |
                                                                          下游服务
```

---

## 配置

### 全局配置（YAML / 环境变量）

```yaml
ai_guard:
  enabled: true
  redis_url: "redis://127.0.0.1:6379"
  default_mode: "enforce"           # observe | enforce
  default_quota_window_secs: 86400  # 配额窗口（秒），0 = 86400
  default_daily_token_quota: 0      # 每用户每窗口 token（0 = 不限）
  default_daily_request_quota: 0    # 每用户每窗口请求数（0 = 不限）
  default_minute_request_quota: 0   # 每用户每分钟请求数（0 = 不限）
  request_body_max_bytes: 0         # 请求体最大字节（0 = 不限）
  default_max_input_tokens: 0       # 输入 token 上限（0 = 不限）
  llm_classifier:
    enabled: false
    endpoint: ""                    # OpenAI 兼容端点
    api_key_env: "AI_CLASSIFIER_API_KEY"
    model: "gpt-4o-mini"
    timeout_ms: 5000
    confidence_threshold: 0.7
    fallback_on_error: "rule"       # rule | allow | deny
```

### 服务级配置（ETCD ServiceAiGuardConfig）

每个服务可独立覆盖全局参数，通过服务注册 API 或管理 UI 配置：

| 参数组 | 字段 | 说明 |
|--------|------|------|
| 基础 | `enabled`, `mode`, `include_paths` | 开关、模式、保护路径 |
| Token 限制 | `max_input_tokens`, `max_output_tokens`, `max_context_tokens` | 输入/输出/历史上限 |
| 配额 | `daily_token_quota`, `daily_request_quota`, `minute_request_quota`, `quota_window_secs` | 用户级配额 |
| 内容审查 | `allow_free_chat`, `allowed_topics`, `deny_keywords` | 话题白名单、关键词黑名单 |
| 业务意图 | `business_description`, `valid_intent_examples`, `invalid_intent_examples` | LLM 分类器业务上下文与示例 |
| 分类器 | `classifier_type`, `llm_endpoint`, `llm_model`, `llm_system_prompt`, `llm_timeout_ms`, `llm_confidence_threshold` | 分类器类型与 LLM 参数（`llm_system_prompt` 为完整自定义 prompt） |
| 请求体 | `request_body_max_bytes`, `body_map`, `history_policy` | 体积限制、字段映射、截断策略 |
| 审计 | `enable_audit` | 是否输出审计事件 |

### LLM 意图分类 Prompt 配置

当 `classifier_type = "llm"` 时，分类器通过 LLM 判断用户请求是否符合业务范围。Prompt 构建有两种方式：

**方式一：完整自定义（`llm_system_prompt`）**

由管理员直接提供完整的 system prompt，网关原样传给 LLM：

```json
{
  "classifier_type": "llm",
  "llm_system_prompt": "You are a classifier for a SQL assistant. Respond ONLY with JSON: {\"allowed\": true, \"reason\": \"...\", \"confidence\": 0.0}. Only allow questions about SQL, databases, and data analysis."
}
```

**方式二：结构化字段自动构建（推荐）**

当 `llm_system_prompt` 为空时，网关从以下三个字段自动组装 prompt，更易维护：

```json
{
  "classifier_type": "llm",
  "business_description": "A coding assistant that helps users write, debug, and review code.",
  "valid_intent_examples": [
    "How do I implement a binary search in Python?",
    "Fix this Rust lifetime error",
    "Explain what this regex does"
  ],
  "invalid_intent_examples": [
    "Write me a poem",
    "What's the capital of France?",
    "Tell me a joke"
  ]
}
```

网关生成的 system prompt 结构如下：

```
You are an AI intent classifier. Determine whether the user's message is a valid business request for this service.

Business context: A coding assistant that helps users write, debug, and review code.

Valid request examples:
- How do I implement a binary search in Python?
- Fix this Rust lifetime error
- Explain what this regex does

Off-topic / invalid examples:
- Write me a poem
- What's the capital of France?
- Tell me a joke

Respond ONLY with JSON: {"allowed": true, "reason": "...", "confidence": 0.0}
```

> 两种方式互斥，`llm_system_prompt` 非空时优先使用，完全忽略 `business_description` 和示例字段。

---

## 请求体字段提取

AI Guard 需要从请求体中识别 `messages`、`prompt`、`model`、`max_tokens` 等字段。提取按三层优先级进行：

### Tier 1: Proto FieldOptions 注解（最高优先级）

在 `.proto` 文件中通过 `AiGuardFieldOptions` 注解标注字段语义：

```protobuf
import "stew/api/v1/options.proto";

message ChatMessage {
  string role    = 1 [(stew.api.v1.ai_guard).is_role_field = true];
  string content = 2 [(stew.api.v1.ai_guard).is_content_field = true];
}

message ChatRequest {
  string model                  = 1 [(stew.api.v1.ai_guard).is_model = true];
  repeated ChatMessage messages = 2 [(stew.api.v1.ai_guard) = {
    is_messages_array: true,
    role_filter: "user"
  }];
  int32 max_tokens              = 3 [(stew.api.v1.ai_guard).is_max_tokens = true];
}
```

可用注解：

| 注解 | 类型 | 说明 |
|------|------|------|
| `is_messages_array` | bool | 消息数组字段 |
| `is_role_field` | bool | 消息中的角色字段 |
| `is_content_field` | bool | 消息中的内容字段 |
| `role_filter` | string | 仅审查指定角色的消息 |
| `is_prompt` | bool | 单一 prompt 字符串 |
| `is_model` | bool | 模型名称字段 |
| `is_max_tokens` | bool | 最大 token 数字段 |

### Tier 2: Body Field Map（ETCD 配置）

通过服务注册时的 `body_map` 字段指定路径映射：

```json
{
  "body_map": {
    "messages_path": "conversation.history",
    "role_field": "speaker",
    "content_field": "text",
    "user_role_value": "human",
    "prompt_path": "input.text",
    "model_path": "config.model",
    "max_tokens_path": "config.max_tokens"
  }
}
```

适用于非标准字段名或无 Proto 定义的 REST 服务。

### Tier 3: OpenAI 兼容格式（兜底）

自动识别 `messages`、`prompt`、`model`、`max_tokens` 等标准 OpenAI API 字段名。

---

## 决策流水线

```
入站请求
  |
1. 路径匹配 -- include_paths 前缀匹配
  |
2. 请求体长度校验 -- > request_body_max_bytes ? -> 400
  |
3. 请求体解析 -- 三层提取策略
  |
4. 关键词扫描 -- deny_keywords 命中 ? -> 403
  |
5. 话题分类 -- allowed_topics + allow_free_chat
  |
6. Token 估算 -- > max_input_tokens ? -> 400
  |
7. 上下文截断 -- history_policy 修剪消息
  |
8. 配额预检 (Redis) -- 分钟/窗口请求数 + 窗口 token
  |
9. 注入预算头 -- x-ai-estimated-tokens, x-ai-max-tokens
  |
10. 放行 -> 下游服务
```

---

## 响应头

### 注入到客户端的响应头

| 头 | 说明 |
|----|------|
| `x-ai-guard-action` | `allow` / `deny` / `truncated` / `observed` |
| `x-ai-guard-reason` | 拒绝或截断原因 |
| `x-ai-quota-remaining-win-tokens` | 当前窗口剩余 token |
| `x-ai-quota-remaining-win-requests` | 当前窗口剩余请求次数 |
| `x-ai-quota-win-reset-secs` | 距窗口重置秒数 |

### 透传给下游的请求头

| 头 | 说明 |
|----|------|
| `x-ai-estimated-tokens` | 估算的输入 token 数 |
| `x-ai-max-tokens` | 输出 token 预算 |

### 下游可选返回的响应头

| 头 | 说明 |
|----|------|
| `x-ai-usage-tokens` | 实际消耗 token 数（用于精确记账） |

---

## 错误响应

| 情形 | HTTP | 说明 |
|------|------|------|
| 请求体超限 | 400 | `request_body_max_bytes` |
| 输入 token 超限 | 400 | `max_input_tokens` |
| 格式无法解析 (enforce) | 400 | 三层提取均失败 |
| 关键词命中 | 403 | `deny_keywords` |
| 话题不相关 | 403 | `allowed_topics` + `allow_free_chat=false` |
| 配额耗尽 | 429 | 窗口 token/请求配额 |
| 分钟限额 | 429 | `minute_request_quota` |

---

## 故障降级

- **Redis 不可达**：fail-open（放行请求），输出告警日志，跳过配额检查
- **LLM 分类器超时/错误**：按 `fallback_on_error` 配置降级（`rule` / `allow` / `deny`）
- **请求体解析失败 + observe 模式**：放行并输出审计事件

---

## 审计事件

启用 `enable_audit` 后，每个 AI Guard 处理的请求会输出结构化审计事件（tracing 日志）：

```json
{
  "request_id": "abc-123",
  "user_id": "user_456",
  "service": "your.ai.v1.AiChatService",
  "path": "/api/v1/ai/chat",
  "model": "gpt-4o",
  "estimated_input_tokens": 1024,
  "max_output_budget": 2048,
  "action": "allow",
  "reason": null,
  "truncated": false,
  "classifier": "rule",
  "ip": "192.168.1.100"
}
```

---

## 源码索引

| 模块 | 文件 | 说明 |
|------|------|------|
| AiGuardMiddleware | `src/middleware/ai_guard.rs` | Phase 1 请求中间件 + Phase 2 body processor |
| AiBodyInspector | `src/middleware/ai_body_inspector.rs` | 三层请求体提取引擎 |
| AiTokenEstimator | `src/middleware/ai_token_estimator.rs` | Token 估算（字符/4 近似） |
| AiClassifier | `src/middleware/ai_classifier.rs` | 规则引擎 + LLM 意图分类 |
| 全局配置 | `src/core/app_config.rs` | `AiGuardConfig` / `LlmClassifierConfig` |
| 服务级配置 | `src/core/service_security_config.rs` | `ServiceAiGuardConfig` 运行时结构体 |
| Proto 注解 | `proto/stew/api/v1/options.proto` | `AiGuardFieldOptions` 消息 + 扩展 50050 |
| 服务配置 Proto | `proto/service_discovery.proto` | `ServiceAiGuardConfig` / `AiBodyFieldMap` |
| 中间件集成 | `src/app/middleware_configurator.rs` | 中间件链注册 |
| 代理集成 | `src/core/hybrid_proxy.rs` | Phase 2 body processor 调用点 |

---

## 相关文档

- [业务接入指南 - AI Guard 接入](业务接入指南.md#十ai-guard-接入指南ai-类接口) -- Proto 注解使用与服务配置
- [AI Guard 设计文档](ai-guard-design.md) -- 完整设计方案、Redis 键设计、测试矩阵
- [中间件](中间件.md) -- 中间件管线总览
