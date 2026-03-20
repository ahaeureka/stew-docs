# AI Guard 中间件技术方案

> 作者: Stew 网关团队  
> 版本: v2.0  
> 日期: 2026-03-20  
> 状态: 方案设计阶段

---

## 1. 背景与目标

AI SaaS 场景中，允许用户自由调用 LLM 会导致 token 消耗失控。本方案在现有 Stew 网关中新增独立的 **AiGuardMiddleware**，在不侵入业务服务的前提下实现：

- 每用户/租户的 token 日额度与分钟请求限额
- **服务级 + 接口级两层配置粒度**，每个 API 端点可独立设置成本控制和意图分类策略
- 请求体长度和输入 token 上限校验
- 上下文历史截断
- 话题/任务分类过滤（防闲聊、防 jailbreak）
- 用量审计事件输出（为计费预留)

**不在本方案范围内**:

- 网关内调用 LLM 做摘要（Phase 2）
- 完整账单闭环（由外部计费服务负责）
- 语义级 embedding 分类（Phase 2）

---

## 2. 架构位置

### 2.1 中间件链顺序

```
[入站请求]
    |
RequestId          <- 注入 x-request-id
    |
RequestIdSpan      <- Tracing span
    |
ClientContext      <- 提取 IP / UA / 国家
    |
RiskAssessment     <- 注入 x-risk-action / x-risk-*
    |
Turnstile          <- CAPTCHA (根据 risk_action 决定)
    |
UnifiedAuth        <- JWT / API Key -> 注入 x-user-id
    |
RateLimit          <- Redis 通用限流 (IP + User)
    |
[AiGuard]          <- AI 专属防滥 (本方案新增)
    |
HttpToGrpcMetadata <- HTTP 头转 gRPC metadata
    |
Logging            <- 请求日志
    |
[下游 AI 服务]
```

> **顺序原则**: 通用 RateLimit 代价低，优先挡刷量；AiGuard 读取请求体代价较高，在认证完成后才能拿到 `x-user-id` 进行用户维度配额。

### 2.2 模块文件清单

| 文件 | 说明 |
|------|------|
| `src/middleware/ai_guard.rs` | AiGuardMiddleware 主实现 |
| `src/middleware/ai_body_inspector.rs` | 请求体字段提取引擎（三层策略：proto options > 字段路径配置 > 启发式兜底） |
| `src/middleware/ai_token_estimator.rs` | 近似 token 估算（无外部调用） |
| `src/middleware/ai_classifier.rs` | `AiIntentClassifier` trait、`RuleBasedClassifier`、`LlmClassifier` |
| `src/middleware/mod.rs` | 导出新模块 |
| `src/core/app_config.rs` | 新增 `AiGuardConfig` |
| `src/core/service_security_config.rs` | 新增 `ServiceAiGuardConfig` + 转换函数 |
| `proto/service_discovery.proto` | 新增 `ServiceAiGuardConfig` message + 字段 40/41 |
| `web/src/pages/Services/securityConfig.ts` | 前端表单值 <-> proto 映射 |
| `web/src/pages/Services/ServiceSecurityFormSection.tsx` | 管理 UI: AI Guard 配置卡片 |

---

## 3. 配置模型

### 3.1 全局配置 `AiGuardConfig` (`src/core/app_config.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiGuardConfig {
    /// 是否在全局开启 AI Guard（各服务可独立覆盖）
    pub enabled: bool,
    /// Redis 地址（通常复用 RateLimitConfig 的 redis_url）
    pub redis_url: String,
    /// 全局默认模式: "observe" | "enforce"
    pub default_mode: String,
    /// 全局默认配额刷新窗口（秒）。
    /// 常用值: 3600 (1小时) | 18000 (5小时) | 86400 (24小时/日)
    /// 0 等效于 86400 (每日重置)
    pub default_quota_window_secs: u32,
    /// 全局默认每用户每窗口 token 配额 (0 = 不限)
    pub default_daily_token_quota: u64,
    /// 全局默认每用户每窗口请求次数配额 (0 = 不限)
    pub default_daily_request_quota: u64,
    /// 全局默认每分钟请求次数 (0 = 不限)
    pub default_minute_request_quota: u32,
    /// 请求体最大字节数 (0 = 不限)
    pub request_body_max_bytes: usize,
    /// 全局默认最大输入 token 估算值 (0 = 不限)
    pub default_max_input_tokens: u32,
    /// 全局 LLM 分类器配置（各服务可通过服务级配置覆盖端点和提示词）
    pub llm_classifier: LlmClassifierConfig,
}

/// 低成本 LLM 意图分类器的全局连接配置。
/// API Key 通过环境变量注入，不存储在配置文件中。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmClassifierConfig {
    /// 是否在全局启用 LLM 分类器（服务级可单独覆盖）
    pub enabled: bool,
    /// 兼容 OpenAI Chat Completions API 的端点，例如：
    ///   https://api.openai.com/v1/chat/completions
    ///   http://localhost:11434/v1/chat/completions  (Ollama)
    pub endpoint: String,
    /// 存储 API Key 的环境变量名（运行时读取，不落配置文件）
    pub api_key_env: String,
    /// 全局默认调用模型，例如 "gpt-4o-mini" / "gemini-1.5-flash"
    pub model: String,
    /// 单次分类请求超时（毫秒）
    pub timeout_ms: u64,
    /// 分类置信度阈值，低于此值时回退到规则分类器
    pub confidence_threshold: f32,
    /// LLM 分类不可用时的降级策略: "rule" | "allow" | "deny"
    pub fallback_on_error: String,
}

impl Default for LlmClassifierConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "https://api.openai.com/v1/chat/completions".to_string(),
            api_key_env: "AI_GUARD_LLM_API_KEY".to_string(),
            model: "gpt-4o-mini".to_string(),
            timeout_ms: 3000,
            confidence_threshold: 0.7,
            fallback_on_error: "rule".to_string(),
        }
    }
}

impl Default for AiGuardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            redis_url: "redis://127.0.0.1:6379".to_string(),
            default_mode: "observe".to_string(),
            default_quota_window_secs: 0,   // 0 = 等效 86400 (日窗口)
            default_daily_token_quota: 0,
            default_daily_request_quota: 0,
            default_minute_request_quota: 0,
            request_body_max_bytes: 0,
            default_max_input_tokens: 0,
            llm_classifier: LlmClassifierConfig::default(),
        }
    }
}
```

### 3.2 服务级 Protobuf 定义 (`proto/service_discovery.proto`)

新增 `ServiceAiGuardConfig` message，并在 `ServiceMiddlewareConfig` 增加 field 40/41：

```protobuf
// AI SaaS 防滥配置
message ServiceAiGuardConfig {
  // 是否开启 AI Guard (false = 跳过所有检查)
  bool enabled = 1;

  // 运行模式: "observe" = 只记录不拦截 | "enforce" = 拦截
  string mode = 2;

  // 仅对匹配以下路径前缀的请求生效；空 = 对所有请求生效
  repeated string include_paths = 3;

  // 请求体大小上限 (bytes，0 = 不限)
  uint32 request_body_max_bytes = 4;

  // 最大输入 token 估算值 (0 = 不限)
  uint32 max_input_tokens = 5;

  // 每次请求的最大输出 token 预算 (0 = 不限，透传给下游)
  uint32 max_output_tokens = 6;

  // 上下文历史最大 token 总量 (0 = 不限)
  uint32 max_context_tokens = 7;

  // 历史截断策略: "truncate_last_n" | "truncate_to_max_tokens"
  string history_policy = 8;

  // 每用户每窗口 token 配额 (0 = 沿用全局默认)
  uint32 daily_token_quota = 9;

  // 每用户每窗口请求次数配额 (0 = 沿用全局默认)
  uint32 daily_request_quota = 10;

  // 每用户每分钟请求次数 (0 = 沿用全局默认)
  uint32 minute_request_quota = 11;

  // 是否允许与产品无关的自由聊天
  bool allow_free_chat = 12;

  // 允许的话题关键词列表（分类器白名单）；空 = 不做话题过滤
  repeated string allowed_topics = 13;

  // 拒绝关键词列表（黑名单，命中即拒绝）
  repeated string deny_keywords = 14;

  // 是否输出审计事件
  bool enable_audit = 15;

  // --- 意图分类器配置 ---

  // 分类器类型: "rule" = 纯规则 | "llm" = LLM + 规则兜底
  // 空字符串时继承全局 LlmClassifierConfig.enabled 决定
  string classifier_type = 16;

  // 覆盖全局 LLM 端点（空 = 沿用全局配置）
  string llm_endpoint = 17;

  // 覆盖全局调用模型（空 = 沿用全局配置），建议使用低成本小模型
  // 例如: "gpt-4o-mini", "gemini-1.5-flash", "qwen-turbo"
  string llm_model = 18;

  // 管理员配置的意图识别系统提示词（System Prompt）。
  // 应描述产品允许的任务范围，LLM 据此判断用户输入是否相关。
  // 示例:
  //   "You are a classifier for a SQL assistant product.
  //    Reply with JSON: {\"allowed\": true/false, \"reason\": \"...\"}.
  //    Only allow questions about SQL, databases, and data analysis."
  string llm_system_prompt = 19;

  // LLM 分类请求超时（毫秒，0 = 沿用全局配置）
  uint32 llm_timeout_ms = 20;

  // 置信度阈值（0.0-1.0，低于此值时回退到规则分类器；0 = 沿用全局配置）
  float llm_confidence_threshold = 21;

  // --- 字段路径映射（Tier 2 提取策略，详见第 16.4 节）---
  // AiBodyFieldMap body_map = 22;

  // --- 配额刷新窗口 ---

  // 配额刷新窗口（秒）。窗口结束后请求计数与 token 计数自动清零。
  // 常用值: 3600 (1小时) | 18000 (5小时) | 43200 (12小时) | 86400 (24小时)
  // 0 = 沿用全局 default_quota_window_secs（默认等效 86400）
  // 窗口槽位计算: slot = unix_timestamp / quota_window_secs
  uint32 quota_window_secs = 23;

  // --- 业务意图配置（LLM 分类器 prompt 构建）---
  // 以下三个字段与 llm_system_prompt 互补：
  //   - 若 llm_system_prompt 非空，则直接使用（完全自定义 prompt）。
  //   - 若 llm_system_prompt 为空，网关自动从以下字段构建意图识别 prompt。

  // 服务用途简介，注入为业务上下文。
  // 示例: "A SQL assistant that helps users write and debug SQL queries."
  string business_description = 24;

  // 有效请求的少样本示例（正例），用于 few-shot 提示。
  // 示例: ["How do I write a GROUP BY query?", "What is the difference between INNER JOIN and LEFT JOIN?"]
  repeated string valid_intent_examples = 25;

  // 无效/偏题请求的少样本示例（负例），用于 few-shot 提示。
  // 示例: ["Write me a poem", "Who is the president of the US?"]
  repeated string invalid_intent_examples = 26;

  // --- 接口级配置覆盖（v2.0 新增，详见第 3.4 节）---
  // 每个接口/端点可独立覆盖服务级默认配置。
  // 匹配到的端点配置中，非零/非空字段覆盖服务级对应值；
  // 未匹配到端点配置的路径使用服务级默认值。
  repeated AiGuardEndpointConfig endpoint_overrides = 27;
}

// 接口级 AI Guard 配置覆盖。
// 每个端点通过 exact_paths（精确匹配）或 prefix_paths（前缀匹配）
// 绑定到具体 API，字段值非零/非空时覆盖服务级默认配置。
// 精确匹配优先于前缀匹配，前缀匹配取最长匹配项。
message AiGuardEndpointConfig {
  // 端点标识名（管理员命名，用于 Redis key 隔离和审计日志）
  // 例如: "chat-send", "embedding", "completion"
  // 同一服务内必须唯一
  string endpoint_id = 1;

  // 精确路径匹配列表
  // 例如: ["/stew.api.v1.ChatService/SendMessage", "/v1/chat/completions"]
  repeated string exact_paths = 2;

  // 前缀路径匹配列表
  // 例如: ["/stew.api.v1.Chat"] 匹配该服务下所有 Chat 开头的方法
  repeated string prefix_paths = 3;

  // 是否禁用该端点的 AI Guard（true = 即使服务级开启也跳过该端点）
  google.protobuf.BoolValue disabled = 4;

  // --- 以下字段全部为覆盖值，0/空 = 继承服务级配置 ---

  string mode = 5;                         // observe / enforce
  uint32 request_body_max_bytes = 6;
  uint32 max_input_tokens = 7;
  uint32 max_output_tokens = 8;
  uint32 max_context_tokens = 9;
  string history_policy = 10;
  uint32 daily_token_quota = 11;
  uint32 daily_request_quota = 12;
  uint32 minute_request_quota = 13;
  uint32 quota_window_secs = 14;
  google.protobuf.BoolValue allow_free_chat = 15;
  repeated string allowed_topics = 16;
  repeated string deny_keywords = 17;
  google.protobuf.BoolValue enable_audit = 18;
  string classifier_type = 19;             // rule / llm
  string llm_endpoint = 20;
  string llm_model = 21;
  string llm_system_prompt = 22;
  string business_description = 23;
  repeated string valid_intent_examples = 24;
  repeated string invalid_intent_examples = 25;
  uint32 llm_timeout_ms = 26;
  float  llm_confidence_threshold = 27;
  AiBodyFieldMap body_map = 28;
}

// 在 ServiceMiddlewareConfig 末尾追加：
//   bool              ai_guard_enabled = 40;
//   ServiceAiGuardConfig ai_guard      = 41;
```

> **bool 字段继承约定**: Protobuf3 的 `bool` 默认值为 `false`，无法区分「管理员显式设为 false」和「未设置/继承」。因此 `AiGuardEndpointConfig` 中的 `disabled`、`allow_free_chat`、`enable_audit` 使用 Proto3 `optional bool` 语法，prost 自动映射为 `Option<bool>`。未设置时为 `None`（继承上层），显式设置时为 `Some(true)` 或 `Some(false)`（覆盖）。

### 3.3 运行时配置结构体 (`src/core/service_security_config.rs`)

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ServiceAiGuardConfig {
    pub enabled: bool,
    pub mode: String,                    // "observe" | "enforce"
    pub include_paths: Vec<String>,
    pub request_body_max_bytes: u32,
    pub max_input_tokens: u32,
    pub max_output_tokens: u32,
    pub max_context_tokens: u32,
    pub history_policy: String,          // "truncate_last_n" | "truncate_to_max_tokens"
    pub daily_token_quota: u32,
    pub daily_request_quota: u32,
    pub minute_request_quota: u32,
    /// 配额刷新窗口（秒）；0 时继承全局 default_quota_window_secs（默认 86400）。
    /// slot = unix_timestamp / quota_window_secs，窗口到期后 Redis key 自然过期。
    pub quota_window_secs: u32,
    pub allow_free_chat: bool,
    pub allowed_topics: Vec<String>,
    pub deny_keywords: Vec<String>,
    pub enable_audit: bool,
    // --- 意图分类器（服务级覆盖）---
    /// "rule" | "llm"；空时继承全局配置
    pub classifier_type: String,
    /// 覆盖全局 LLM 端点；空时继承全局
    pub llm_endpoint: Option<String>,
    /// 覆盖全局模型；空时继承全局
    pub llm_model: Option<String>,
    /// 管理员在服务注册/编辑界面填写的系统提示词（完整自定义 prompt）。
    /// 非空时直接作为 LLM 分类器的 system prompt，忽略 business_description 等结构化字段。
    pub llm_system_prompt: Option<String>,
    /// 服务用途简介；llm_system_prompt 为空时用于自动构建意图识别 prompt。
    pub business_description: Option<String>,
    /// 有效请求少样本示例（正例，few-shot）。
    pub valid_intent_examples: Vec<String>,
    /// 无效/偏题请求少样本示例（负例，few-shot）。
    pub invalid_intent_examples: Vec<String>,
    /// 超时毫秒；0 时继承全局
    pub llm_timeout_ms: u32,
    /// 置信度阈值；0.0 时继承全局
    pub llm_confidence_threshold: f32,
    /// 接口级配置覆盖列表（v2.0 新增）
    pub endpoint_overrides: Vec<EndpointAiGuardConfig>,
}
```

### 3.4 接口级配置模型（v2.0 新增）

#### 3.4.1 设计动机

同一业务服务下的不同 API 接口往往有截然不同的成本模型和安全需求：

| 接口 | 成本特征 | 安全需求 |
|------|----------|----------|
| `/v1/chat/completions` | 高成本（GPT-4 级别） | 严格配额 + 意图分类 |
| `/v1/embeddings` | 低成本（embedding 模型） | 宽配额，无需分类 |
| `/v1/models` | 零成本（元数据查询） | 可跳过 AI Guard |
| `/v1/images/generations` | 极高成本（DALL-E） | 极低配额 + 内容审查 |

服务级配置无法覆盖这种差异化需求。接口级配置允许管理员对每个 API 端点独立设置配额、分类策略和审计行为。

#### 3.4.2 配置解析优先级

```
接口级 (endpoint_overrides 中匹配项的非零/非空字段)
  > 服务级 (ServiceAiGuardConfig 基础字段)
    > 全局 (AiGuardConfig)
      > 内置默认值
```

**路径匹配优先级**（同一请求可能匹配多个端点配置时）：

1. **精确匹配**优先于前缀匹配
2. 多个前缀匹配时取**最长前缀**
3. 无匹配时使用服务级默认配置

#### 3.4.3 `EndpointAiGuardConfig` 运行时结构体

```rust
/// 接口级 AI Guard 配置覆盖。
/// 字段为 0/空/None 时表示继承服务级配置。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct EndpointAiGuardConfig {
    /// 端点标识名（管理员命名，用于 Redis key 和 audit 日志）
    pub endpoint_id: String,
    /// 精确匹配路径列表
    pub exact_paths: Vec<String>,
    /// 前缀匹配路径列表
    pub prefix_paths: Vec<String>,
    /// 是否禁用该端点的 AI Guard
    pub disabled: Option<bool>,
    pub mode: String,
    pub request_body_max_bytes: u32,
    pub max_input_tokens: u32,
    pub max_output_tokens: u32,
    pub max_context_tokens: u32,
    pub history_policy: String,
    pub daily_token_quota: u32,
    pub daily_request_quota: u32,
    pub minute_request_quota: u32,
    pub quota_window_secs: u32,
    pub allow_free_chat: Option<bool>,
    pub allowed_topics: Vec<String>,
    pub deny_keywords: Vec<String>,
    pub enable_audit: Option<bool>,
    pub classifier_type: String,
    pub llm_endpoint: Option<String>,
    pub llm_model: Option<String>,
    pub llm_system_prompt: Option<String>,
    pub business_description: Option<String>,
    pub valid_intent_examples: Vec<String>,
    pub invalid_intent_examples: Vec<String>,
    pub llm_timeout_ms: u32,
    pub llm_confidence_threshold: f32,
}
```

#### 3.4.4 路径匹配方法

```rust
impl EndpointAiGuardConfig {
    /// 检查路径是否匹配此端点配置
    pub fn matches(&self, path: &str) -> bool {
        self.exact_paths.iter().any(|p| p == path)
            || self.prefix_paths.iter().any(|p| path.starts_with(p))
    }

    /// 是否为精确匹配（用于优先级判断）
    pub fn is_exact_match(&self, path: &str) -> bool {
        self.exact_paths.iter().any(|p| p == path)
    }

    /// 获取匹配到的最长前缀长度（用于优先级排序）
    pub fn longest_prefix_len(&self, path: &str) -> usize {
        self.prefix_paths
            .iter()
            .filter(|p| path.starts_with(p.as_str()))
            .map(|p| p.len())
            .max()
            .unwrap_or(0)
    }
}
```

#### 3.4.5 端点配置查找与合并

```rust
impl ServiceAiGuardConfig {
    /// 查找最佳匹配的端点配置。
    /// 精确匹配优先于前缀匹配，前缀匹配取最长匹配项。
    pub fn find_endpoint_override(&self, path: &str) -> Option<&EndpointAiGuardConfig> {
        // 1. 精确匹配优先
        if let Some(ep) = self.endpoint_overrides.iter()
            .find(|ep| ep.is_exact_match(path)) {
            return Some(ep);
        }
        // 2. 前缀匹配（最长前缀优先）
        self.endpoint_overrides.iter()
            .filter(|ep| ep.matches(path))
            .max_by_key(|ep| ep.longest_prefix_len(path))
    }

    /// 将服务级配置与端点级覆盖合并，返回最终生效配置。
    /// 端点级非零/非空字段覆盖服务级对应值。
    pub fn resolve_for_path(&self, path: &str) -> ResolvedAiGuardConfig {
        let ep = self.find_endpoint_override(path);
        ResolvedAiGuardConfig {
            endpoint_id: ep.map(|e| e.endpoint_id.clone()),
            mode: ep.and_then(|e| non_empty(&e.mode))
                .unwrap_or_else(|| self.mode.clone()),
            request_body_max_bytes: ep.map(|e| e.request_body_max_bytes)
                .filter(|v| *v > 0)
                .unwrap_or(self.request_body_max_bytes),
            max_input_tokens: ep.map(|e| e.max_input_tokens)
                .filter(|v| *v > 0)
                .unwrap_or(self.max_input_tokens),
            // ... 其余 u32/String 字段同理: 非零/非空时覆盖 ...
            allow_free_chat: ep.and_then(|e| e.allow_free_chat)
                .unwrap_or(self.allow_free_chat),
            enable_audit: ep.and_then(|e| e.enable_audit)
                .unwrap_or(self.enable_audit),
            deny_keywords: ep.map(|e| &e.deny_keywords)
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| self.deny_keywords.clone()),
            // ... 其余 Vec<String> 字段同理: 非空时覆盖 ...
        }
    }
}
```

#### 3.4.6 `ResolvedAiGuardConfig` 最终配置

合并后的最终配置结构体，消除运行时的覆盖判断，中间件直接使用：

```rust
/// 三层合并后的最终 AI Guard 配置。
/// 由 ServiceAiGuardConfig::resolve_for_path() 生成。
#[derive(Debug, Clone)]
pub struct ResolvedAiGuardConfig {
    /// 匹配到的端点标识（None = 使用服务级默认配置）
    pub endpoint_id: Option<String>,
    pub mode: String,
    pub request_body_max_bytes: u32,
    pub max_input_tokens: u32,
    pub max_output_tokens: u32,
    pub max_context_tokens: u32,
    pub history_policy: String,
    pub daily_token_quota: u32,
    pub daily_request_quota: u32,
    pub minute_request_quota: u32,
    pub quota_window_secs: u32,
    pub allow_free_chat: bool,
    pub allowed_topics: Vec<String>,
    pub deny_keywords: Vec<String>,
    pub enable_audit: bool,
    pub classifier_type: String,
    pub llm_endpoint: Option<String>,
    pub llm_model: Option<String>,
    pub llm_system_prompt: Option<String>,
    pub business_description: Option<String>,
    pub valid_intent_examples: Vec<String>,
    pub invalid_intent_examples: Vec<String>,
    pub llm_timeout_ms: u32,
    pub llm_confidence_threshold: f32,
}
```

#### 3.4.7 字段覆盖规则总结

| 字段类型 | 覆盖条件 | 继承条件 | 示例 |
|----------|----------|----------|------|
| `u32` / `u64` | 值 > 0 | 值 == 0 | `max_input_tokens: 0` = 继承 |
| `String` | 非空字符串 | 空字符串 | `mode: ""` = 继承 |
| `Vec<String>` | 数组非空 | 数组为空 | `deny_keywords: []` = 继承 |
| `Option<bool>` | `Some(v)` | `None` | `allow_free_chat: None` = 继承 |
| `f32` | 值 > 0.0 | 值 == 0.0 | `llm_confidence_threshold: 0.0` = 继承 |
| `Option<String>` | `Some(非空)` | `None` 或 `Some("")` | `llm_endpoint: None` = 继承 |

#### 3.4.8 配置示例

```yaml
# 服务: stew.api.v1.AiAssistantService
# 服务级默认配置
ai_guard:
  enabled: true
  mode: enforce
  daily_token_quota: 100000
  daily_request_quota: 500
  minute_request_quota: 20
  deny_keywords: ["jailbreak", "ignore previous"]
  classifier_type: rule

  # 接口级覆盖
  endpoint_overrides:
    - endpoint_id: chat-gpt4
      exact_paths:
        - /stew.api.v1.AiAssistantService/ChatGPT4
        - /v1/chat/completions/gpt4
      # GPT-4 成本高，使用严格配额
      daily_token_quota: 10000
      daily_request_quota: 50
      minute_request_quota: 5
      max_input_tokens: 4096
      max_output_tokens: 2048
      classifier_type: llm
      business_description: "GPT-4 powered deep analysis assistant"

    - endpoint_id: embedding
      prefix_paths:
        - /stew.api.v1.AiAssistantService/Embed
        - /v1/embeddings
      # Embedding 成本低，配额宽松
      daily_token_quota: 1000000
      daily_request_quota: 5000
      minute_request_quota: 100
      # 不需要意图分类
      allow_free_chat: true

    - endpoint_id: models-meta
      exact_paths:
        - /stew.api.v1.AiAssistantService/ListModels
        - /v1/models
      # 元数据查询，完全跳过 AI Guard
      disabled: true
```

---

## 4. 决策流水线

AiGuard 的 `handle()` 函数按以下顺序执行：

```
入站请求
    |
1. 入口匹配 + 接口级配置解析
   - 服务名 / 路径前缀是否在 include_paths 内
   - ai_guard_enabled == false ? 直接放行
   - 查找 endpoint_overrides 匹配项:
     - 精确匹配优先 > 最长前缀匹配 > 服务级默认
     - 匹配的 endpoint.disabled == true ? 跳过该端点
   - 调用 resolve_for_path() 合并三层配置
    |
2. 请求体读取与长度校验
   - 读取 body bytes（替换 body 以便后续中间件继续使用）
   - bytes > request_body_max_bytes ? -> 400 BadRequest
    |
3. 请求体解析 (yong)
   - 解析 messages / prompt / input / model / max_tokens
   - 无法识别格式 + mode=observe ? -> 放行并打 audit 事件
   - 无法识别格式 + mode=enforce ? -> 400 BadRequest
    |
4. 拒绝关键词扫描 (AiClassifier)
   - 检查 deny_keywords 黑名单
   - 命中 -> 403 Forbidden
    |
5. 话题分类 (AiClassifier)
   - allowed_topics 非空 && allow_free_chat=false ?
   - 分类器判定不相关 + mode=enforce -> 403 Forbidden
   - mode=observe -> 放行并打 audit 事件
    |
6. Token 估算 (AiTokenEstimator)
   - 估算 input token 数
   - estimated > max_input_tokens -> 400 BadRequest
    |
7. 上下文截断 (history_policy)
   - truncate_last_n: 保留最近 N 条 messages
   - truncate_to_max_tokens: 移除最旧消息直到估算值 <= max_context_tokens
   - 修改请求体后重新序列化
    |
8. 配额预检查 (Redis)
   - 分钟请求次数: key = ai:rl:min:{user_id}[:{endpoint_id}]:{unix_seconds/60}
   - 窗口请求次数: key = ai:quota:win:{window_secs}:req:{user_id}[:{endpoint_id}]:{slot}
   - 窗口 token:   key = ai:quota:win:{window_secs}:tok:{user_id}[:{endpoint_id}]:{slot}
   - 有 endpoint 匹配时 key 中包含 endpoint_id，无匹配时省略（向后兼容）
   - window_secs  = quota_window_secs (接口级/服务级) ?? default_quota_window_secs (全局) ?? 86400
   - TTL          = window_secs * 2（保证跨两倍窗口长度自动清理）
   - 任意超限 -> 429 TooManyRequests
   - Redis 故障 -> fail-open: 放行并打告警日志
    |
9. 注入预算头
   - x-ai-max-tokens: max_output_tokens (透传给下游 AI 服务)
   - x-ai-estimated-tokens: 估算输入 token 数
    |
10. 放行请求
    |
[下游 AI 服务响应后]
    |
11. 用量记账 (ResponseMiddleware)
    - 读取 x-ai-usage-tokens 响应头（下游可选填写）
    - 更新 Redis 日 token 计数
    - 输出审计日志事件
```

---

## 5. 核心数据结构

### 5.1 AiRequestEnvelope (解析后的请求)

```rust
#[derive(Debug, Default)]
pub struct AiRequestEnvelope {
    /// 原始模型名称 (e.g. "gpt-4o", "claude-3-5-sonnet")
    pub model: Option<String>,
    /// 消息列表 (ChatCompletion 格式)
    pub messages: Option<Vec<AiMessage>>,
    /// 简单 prompt 字符串 (Completion 格式)
    pub prompt: Option<String>,
    /// 自定义 input 字段 (embedding/其他 API)
    pub input: Option<String>,
    /// 客户端期望的 max_tokens
    pub max_tokens: Option<u32>,
    /// 是否为流式请求
    pub stream: bool,
}

#[derive(Debug, Clone)]
pub struct AiMessage {
    pub role: String,
    pub content: String,
}
```

### 5.2 AiGuardDecision (决策结果)

```rust
#[derive(Debug, PartialEq)]
pub enum AiGuardAction {
    Allow,
    Deny(AiGuardDenyReason),
    Truncated,   // 放行但已修改请求体
    Observed,    // observe 模式: 本应拒绝但未拦截
}

#[derive(Debug, PartialEq)]
pub enum AiGuardDenyReason {
    BodyTooLarge,
    InputTooLong,
    DenyKeywordMatched(String),
    OffTopic,
    QuotaExhausted,
    RateLimited,
    ParseError,
}
```

### 5.3 AiGuardAuditEvent (审计事件)

```rust
#[derive(Debug, Serialize)]
pub struct AiGuardAuditEvent {
    pub request_id: String,
    pub user_id: Option<String>,
    pub service: String,
    pub path: String,
    /// 匹配到的端点标识（None = 使用服务级默认配置）
    pub endpoint_id: Option<String>,
    pub model: Option<String>,
    pub estimated_input_tokens: u32,
    pub max_output_budget: u32,
    pub action: String,
    pub reason: Option<String>,
    pub truncated: bool,
    pub risk_action: Option<String>,
    pub ip: Option<String>,
}
```

---

## 6. Redis 键设计

| 用途 | Key 模式 | TTL |
|------|----------|-----|
| 分钟请求计数（服务级） | `ai:rl:min:{user_id}:{unix_seconds/60}` | 120s |
| 分钟请求计数（接口级） | `ai:rl:min:{user_id}:{endpoint_id}:{unix_seconds/60}` | 120s |
| 窗口请求计数（服务级） | `ai:quota:win:{window_secs}:req:{user_id}:{slot}` | `window_secs * 2` |
| 窗口请求计数（接口级） | `ai:quota:win:{window_secs}:req:{user_id}:{endpoint_id}:{slot}` | `window_secs * 2` |
| 窗口 token 计数（服务级） | `ai:quota:win:{window_secs}:tok:{user_id}:{slot}` | `window_secs * 2` |
| 窗口 token 计数（接口级） | `ai:quota:win:{window_secs}:tok:{user_id}:{endpoint_id}:{slot}` | `window_secs * 2` |

**接口级配额隔离设计**：当请求匹配到某个 `endpoint_override` 时，Redis key 中加入 `endpoint_id` 字段，使该端点的配额计数与其他端点完全隔离。未匹配任何端点配置的请求使用不含 `endpoint_id` 的服务级 key（与 v1.0 行为一致）。

`window_secs` 解析优先级：接口级 `quota_window_secs` > 服务级 `quota_window_secs` > 全局 `default_quota_window_secs` > 默认 `86400`。

**窗口槽位计算示例**（`slot = unix_timestamp / window_secs`）：

| 配额周期 | window_secs | unix_ts = 1710748800 时的 slot | Redis TTL |
|----------|-------------|--------------------------------|-----------|
| 1 小时重置 | 3600 | 475208 | 7200s (2h) |
| 5 小时重置 | 18000 | 95041 | 36000s (10h) |
| 每日重置 | 86400 | 19800 | 172800s (48h) |

**设计要点**：
- `window_secs` 编码在 key 中，不同窗口长度的计数相互独立，修改 `quota_window_secs` 时旧 key 随 TTL 自然销毁，无需手动清理
- 窗口刷新为自然周期（slot 切换），不对齐到整点；如需整点对齐（如每天零点），将 `window_secs = 86400` 并在写入时计算 `today_epoch = floor(unix_ts / 86400) * 86400`
- `user_id` 来源优先级: `x-user-id` 头 > API Key ID > Client IP（最低可信）
- 键前缀与现有 RateLimit (`stew:rl:*`) 隔离，避免碰撞

---

## 7. 响应头约定

| 头 | 方向 | 说明 |
|----|------|------|
| `x-ai-guard-action` | response | 决策：allow / deny / truncated / observed |
| `x-ai-guard-reason` | response | 拒绝或截断原因（仅 enforce 模式） |
| `x-ai-guard-endpoint` | response | 匹配到的 endpoint_id（未匹配时不输出） |
| `x-ai-quota-remaining-win-tokens` | response | 当前窗口剩余 token 配额 |
| `x-ai-quota-remaining-win-requests` | response | 当前窗口剩余请求次数 |
| `x-ai-quota-win-reset-secs` | response | 当前配额窗口距重置的剩余秒数 |
| `x-ai-estimated-tokens` | request (downstream) | 估算输入 token，透传给后端 |
| `x-ai-max-tokens` | request (downstream) | max_output_tokens 预算，透传给后端 |
| `x-ai-usage-tokens` | response (from backend) | 后端实际消耗 token（用于记账） |

---

## 8. 错误响应映射

| 情形 | HTTP 状态码 | MiddlewareError 变体 |
|------|-------------|----------------------|
| 请求体超限 | 400 | `BadRequest` |
| 输入 token 超限 | 400 | `BadRequest` |
| 格式无法解析 (enforce) | 400 | `BadRequest` |
| 话题不相关 / jailbreak | 403 | `Forbidden` |
| 拒绝关键词命中 | 403 | `Forbidden` |
| 日配额耗尽 | 429 | `TooManyRequests` |
| 分钟限额超限 | 429 | `TooManyRequests` |

---

## 9. AiTokenEstimator 算法

Phase 1 不调用外部 API，采用近似规则：

1. 对于 messages 格式，拼接所有 `role: content` 文本
2. 按空格/标点分词，token 估算 = `word_count * 1.3`（英文）
3. 中文字符每个字 ≈ 1.5 tokens
4. 混合内容按各占比加权
5. 误差在 ±20%，满足预检场景

**精确计价由下游服务返回 `x-ai-usage-tokens` 后覆盖。**

---

## 10. AiClassifier trait 设计

```rust
#[async_trait]
pub trait AiIntentClassifier: Send + Sync {
    async fn classify(&self, envelope: &AiRequestEnvelope) -> ClassifierResult;
}

pub struct ClassifierResult {
    pub is_allowed: bool,
    pub matched_topic: Option<String>,
    pub matched_deny_keyword: Option<String>,
    /// 0.0 - 1.0；规则分类器始终返回 1.0
    pub confidence: f32,
    /// 分类来源标识，用于 audit 事件
    pub classifier: ClassifierKind,
}

pub enum ClassifierKind {
    Rule,
    Llm,
    Fallback, // LLM 失败后由规则兜底
}
```

### 10.1 RuleBasedClassifier（Phase 1，默认实现）

- `deny_keywords` 黑名单：优先精确匹配，其次包含匹配，O(n) 扫描
- `allowed_topics` 白名单：消息文本是否包含任意白名单词（不区分大小写）
- 不发起任何外部请求，延迟 < 1ms
- confidence 固定返回 `1.0`

### 10.2 LlmClassifier（Phase 1，可选启用）

通过管理员在服务级配置填写的 **System Prompt** + 低成本 LLM（如 `gpt-4o-mini`、`gemini-1.5-flash`、本地 Ollama 模型）对用户输入做意图分类。

**依赖**：使用 [`openai-api-rs`](https://crates.io/crates/openai-api-rs) crate，它提供兼容 OpenAI Chat Completions 协议的 Rust 客户端，支持自定义 `api_endpoint`，因此可直接对接 Ollama、Azure OpenAI、Gemini OpenAI 兼容接口等任意兼容后端。

```toml
# Cargo.toml（stew workspace member）
[dependencies]
openai-api-rs = "6"
```

**Rust 实现骨架**：

```rust
use openai_api_rs::v1::api::OpenAIClient;
use openai_api_rs::v1::chat_completion::{self, ChatCompletionRequest};
use openai_api_rs::v1::common::GPT4_O_MINI;

pub struct LlmClassifier {
    config: LlmResolvedConfig,
}

impl LlmClassifier {
    pub fn new(config: LlmResolvedConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl AiIntentClassifier for LlmClassifier {
    async fn classify(&self, envelope: &AiRequestEnvelope) -> ClassifierResult {
        let user_text = extract_last_user_message(envelope);
        let system_content = format!(
            "{}\n\nRespond ONLY with JSON: {{\"allowed\": true|false, \"reason\": \"...\", \"confidence\": 0.0-1.0}}",
            self.config.system_prompt
        );

        // openai-api-rs 支持通过 api_endpoint 对接任意兼容后端
        let client = OpenAIClient::builder()
            .with_endpoint(self.config.endpoint.clone())
            .with_api_key(self.config.api_key.clone())
            .build()
            .unwrap_or_else(|_| return ClassifierResult::fallback());

        let req = ChatCompletionRequest::new(
            self.config.model.clone(),
            vec![
                chat_completion::ChatCompletionMessage {
                    role: chat_completion::MessageRole::system,
                    content: chat_completion::Content::Text(system_content),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
                chat_completion::ChatCompletionMessage {
                    role: chat_completion::MessageRole::user,
                    content: chat_completion::Content::Text(user_text),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
            ],
        )
        .temperature(0.0)
        .max_tokens(64u32);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(self.config.timeout_ms),
            client.chat_completion(req),
        )
        .await;

        match result {
            Ok(Ok(resp)) => parse_llm_response(resp, self.config.confidence_threshold),
            _ => ClassifierResult::fallback_with(self.config.fallback_on_error.clone()),
        }
    }
}
```

> `LlmResolvedConfig` 是运行时将服务级覆盖与全局 `LlmClassifierConfig` 合并后的最终配置，由 `AiGuardMiddleware` 在初始化或每次请求时构造。

**System Prompt 示例**（管理员在服务编辑界面填写）：

```
You are an intent classifier for a SQL assistant product.
Only allow questions about SQL queries, database design, and data analysis.
Reject casual chat, creative writing, code in non-SQL languages, or off-topic requests.
Respond ONLY with JSON: {"allowed": true|false, "reason": "...", "confidence": 0.0-1.0}
```

**降级策略**（`fallback_on_error`）：

| 情形 | 行为 |
|------|------|
| LLM 超时 / 网络错误 | 按 `fallback_on_error` 配置: `rule` = 回退规则分类器 / `allow` = 直接放行 / `deny` = 拒绝 |
| JSON 解析失败 | 同上降级 |
| confidence < threshold | 回退到 `RuleBasedClassifier` 再判一次 |
| observe 模式 | 无论结果如何，均放行并在 audit 事件中记录 LLM 决策 |

**性能约束**：
- 分类调用只传最后一条用户消息（不传完整历史），控制 prompt token 开销
- `llm_timeout_ms` 默认 3000ms；超时即触发降级，不阻塞主链路
- 所有 LLM 分类器调用前先执行 `RuleBasedClassifier` 的 `deny_keywords` 扫描，命中黑名单直接拒绝，不消耗 LLM token

**Phase 2 预留**: `EmbeddingClassifier` / `RemoteClassifierAdapter`（实现同一 `AiIntentClassifier` trait）

---

## 11. 上下文截断策略

### truncate_last_n_messages

保留最后 N 条 messages（N 由 `max_context_tokens / avg_msg_tokens` 估算），超出部分从最早的消息开始删除，保留 `system` 角色消息不删除。

### truncate_to_max_tokens

估算 messages 总 token，若超过 `max_context_tokens`，循环移除最早的非 system 消息，直到满足限制。

---

## 12. 故障降级策略

| 组件故障 | 行为 |
|----------|------|
| Redis 不可用 | Fail-open: 跳过配额检查，输出 WARN 日志，记录 audit 事件 |
| LLM 分类器超时/网络错误 | 按 `fallback_on_error` 策略（默认回退 `RuleBasedClassifier`），audit 标记 `classifier=Fallback` |
| LLM 响应 JSON 解析失败 | 同上降级 |
| 规则分类器执行异常 | Fail-open: 按 allow 处理，audit 事件标记 `classification_unknown` |
| 请求体无法解析 | observe 模式 fail-open；enforce 模式返回 400 |
| ETCD 配置不可用 | 使用全局 `AiGuardConfig` 默认值 |

---

## 13. 实现分阶段计划

### Phase 1（最小可用版本） -- 已完成

目标：能拦截明显滥用，验证链路可用，observe 模式上线，管理员可通过现有服务管理页面对每个服务独立配置 AI Guard。

**后端**
- [x] `proto/stew/api/v1/options.proto`: 新增 `AiGuardFieldOptions` FieldOptions 扩展（field 50050+）
- [x] `proto/service_discovery.proto`: 新增 `ServiceAiGuardConfig` (field 40/41)
- [x] `src/core/app_config.rs`: 新增 `AiGuardConfig` + `LlmClassifierConfig`
- [x] `src/core/service_security_config.rs`: 新增 `ServiceAiGuardConfig` + 转换函数
- [x] `src/middleware/ai_guard.rs`: 两阶段架构 -- Phase 1 请求中间件 + Phase 2 AiGuardBodyProcessor
- [x] `src/middleware/ai_body_inspector.rs`: 三层提取引擎（Proto 注解 > BodyMap > OpenAI 兼容）
- [x] `src/middleware/ai_token_estimator.rs`: 近似 token 估算（字符/4）
- [x] `src/middleware/ai_classifier.rs`: `AiIntentClassifier` trait + `RuleBasedClassifier` + `LlmClassifier`
- [x] `src/app/middleware_configurator.rs`: 链中插入 `AiGuardMiddleware`
- [x] `src/middleware/mod.rs`: 导出新模块

**前端（服务级一对一配置，详见第 17 节）**
- [x] `web/src/pages/Services/securityConfig.ts`: 扩展 `ServiceSecurityFormValue` + `ai_guard` 字段映射
- [x] `web/src/pages/Services/ServiceSecurityFormSection.tsx`: 新增 AI Guard 配置卡片（嵌入现有服务注册/编辑/查看表单）

**文档**
- [x] `docs/业务接入指南.md`: 新增 1.4 AI Guard 字段注解 + 第十节 AI Guard 接入指南
- [x] `docs/中间件.md`: 管线图更新 + AiGuardMiddleware 章节
- [x] `docs/ai中间件.md`: 完整 Stew AI Guard 中间件技术文档

### Phase 1.5（接口级配置粒度）

目标：将 AI Guard 防护下放到接口一级，每个 API 端点可独立设置成本控制和意图分类策略。

**Proto 层**
- [ ] `proto/service_discovery.proto`: 新增 `AiGuardEndpointConfig` message，`ServiceAiGuardConfig` 追加 `endpoint_overrides` 字段 27

**后端**
- [ ] `src/core/service_security_config.rs`: 新增 `EndpointAiGuardConfig` + `ResolvedAiGuardConfig` struct，新增 `find_endpoint_override()` + `resolve_for_path()` 方法，扩展 `convert_ai_guard_config()` 处理 endpoint_overrides 数组
- [ ] `src/middleware/ai_guard.rs`: Phase 1 中增加端点配置查找和合并逻辑，`AiGuardPendingCheck` 新增 `endpoint_id`，Redis key 加入 endpoint 标识，`AiGuardAuditEvent` 新增 `endpoint_id`

**前端**
- [ ] `web/src/pages/Services/securityConfig.ts`: 新增 `AiGuardEndpointFormValue` 接口，`AiGuardFormValue` 追加 `endpoint_overrides`，序列化/反序列化扩展
- [ ] `web/src/pages/Services/ServiceSecurityFormSection.tsx`: 使用 `Form.List` 实现动态增删端点配置表单
- [ ] `web/src/pages/Services/Discovery.tsx`: 展示已配置的接口级覆盖列表

**文档**
- [ ] `docs/ai-guard-design.md`: 新增接口级配置模型章节（本文档）
- [ ] `docs/ai中间件.md`: 同步更新接口级配置说明

### Phase 2（增强版本）

- [ ] 摘要式历史压缩（调用小模型接口）
- [ ] `EmbeddingClassifier` 接入外部 embedding 服务
- [ ] 流式响应双阶段记账（预扣 + 结算）
- [ ] 租户维度配额支持（多用户共享日额度池）
- [ ] Prometheus 指标导出（`ai_guard_allow_total`, `ai_guard_deny_total` 等）

---

## 14. 测试矩阵

| 测试场景 | 验证要点 |
|----------|----------|
| 正常 AI 请求 | 全流程放行，audit 事件输出 |
| 未认证用户 | 回退到 IP 维度配额 |
| 免费用户日配额耗尽 | 返回 429，响应头含 `x-ai-quota-remaining-*` |
| 超大请求体 | 返回 400，body 不转发到下游 |
| 超长 messages 历史 | 截断后转发，audit 标记 truncated |
| 无关闲聊拦截 | enforce 模式返回 403，observe 模式放行 |
| deny_keywords 命中 | enforce 直接 403，不调用分类器 |
| Redis 故障 | 说明: fail-open 放行，WARN 日志出现 |
| 格式无法识别 | observe 放行；enforce 返回 400 |
| ai_guard_enabled=false | 整个中间件直接跳过 |
| include_paths 不匹配 | 跳过检查，直接放行 |
| --- 接口级配置场景 --- | --- |
| 端点精确匹配 | 使用端点配置，audit 中包含 endpoint_id |
| 端点前缀匹配 | 匹配最长前缀，使用对应端点配置 |
| 多个端点前缀匹配冲突 | 取最长前缀匹配项 |
| endpoint.disabled=true | 跳过该端点所有 AI Guard 检查 |
| 端点级配额与服务级配额隔离 | Redis key 含 endpoint_id，计数器独立 |
| 端点级字段为0/空 | 继承服务级对应值，不报错 |
| 端点级分类器与服务级不同 | 端点级 classifier_type 覆盖服务级 |
| 未匹配任何端点 | 使用服务级默认配置（向后兼容） |
| endpoint_id 重复 | 后端去重取第一个，前端校验拒绝保存 |

---

## 15. 与现有中间件的集成要点

1. **x-user-id**: 由 `UnifiedAuthMiddleware` 注入，AiGuard 读取此头作为用户维度主键；若缺失则降级为 Client IP（来自 `ClientContextMiddleware` 注入的 `x-client-ip`）。
2. **x-risk-action**: 由 `RiskAssessmentMiddleware` 注入；AiGuard 在 mode=enforce 时可结合 risk_action=block 提前拒绝 AI 请求，无需等到话题分类。
3. **MiddlewareError**: 使用 `crate::core::middleware::MiddlewareError`（含 `TooManyRequests` 变体），**不使用** `core::middleware_interface::MiddlewareError`。
4. **ETCD 热更新**: 服务级配置存储在 `ServiceInstance.middleware_config.ai_guard`，通过 `EtcdServiceDiscovery` 缓存热生效，无需重启网关。
5. **请求体读取**: Hyper `Incoming` body 只能消费一次；AiGuard 读取后需将字节重新封装回 `Request<BoxBody>` 传给后续中间件。

---

## 16. AiBodyInspector 提取引擎设计

### 16.1 问题背景

网关代理的 AI 服务可能使用不同的 JSON 请求格式（OpenAI ChatCompletion、Anthropic Messages、自定义格式），也可能是有完整 Protobuf descriptor 的 gRPC 服务。`AiBodyInspector` 需要在不了解具体业务结构的前提下，从请求体中提取：

- **用户消息文本** — 用于意图分类和 token 估算
- **完整消息历史** — 用于上下文截断后重新序列化
- **模型名称** — 用于计费路由
- **max_tokens** — 用于透传预算头

### 16.2 三层提取策略（优先级从高到低）

```
[优先级 1] Proto FieldOptions 注解
    读取 DescriptorManager 中已加载的服务描述符
    查找带有 (stew.api.v1.ai_guard).* 注解的字段
    ↓ (descriptor 不可用或无注解)
[优先级 2] 服务级字段路径配置
    ServiceAiGuardConfig.body_map 中管理员配置的字段路径表达式
    支持: "messages[role=user].content" 语法
    ↓ (未配置)
[优先级 3] 启发式兜底
    按顺序尝试已知字段名: messages / prompt / input / query
    messages 数组默认取 role==user 的 content
```

### 16.3 Proto FieldOptions 扩展 (`proto/stew/api/v1/options.proto`)

在现有 `FieldOptions` 扩展（50039–50040）之后，新增 AI Guard 字段标注（从 50050 开始）：

```protobuf
// AI Guard 字段语义标注
message AiGuardFieldOptions {
  // 该字段是消息数组（对应 AI 对话历史）
  bool is_messages_array = 1;
  // 该字段是消息中的角色标识（如 "role"）
  bool is_role_field = 2;
  // 该字段是消息中的文本内容（如 "content"）
  bool is_content_field = 3;
  // 只提取 role 字段等于此值的消息内容（空 = 提取全部）
  string role_filter = 4;
  // 该字段是单一 prompt 字符串（非对话格式）
  bool is_prompt = 5;
  // 该字段是模型名称
  bool is_model = 6;
  // 该字段是 max_tokens 提示
  bool is_max_tokens = 7;
}

extend google.protobuf.FieldOptions {
  optional AiGuardFieldOptions ai_guard = 50050;
}
```

**业务 Proto 使用示例**（服务方在自己的 proto 中标注）：

```protobuf
message ChatRequest {
  string model     = 1 [(stew.api.v1.ai_guard).is_model = true];
  repeated Message messages = 2 [(stew.api.v1.ai_guard).is_messages_array = true];
  uint32 max_tokens = 3 [(stew.api.v1.ai_guard).is_max_tokens = true];
}

message Message {
  string role    = 1 [(stew.api.v1.ai_guard).is_role_field = true];
  // role_filter = "user" 表示仅当 role == "user" 时此字段的内容才被提取用于分类
  string content = 2 [
    (stew.api.v1.ai_guard).is_content_field = true,
    (stew.api.v1.ai_guard).role_filter = "user"
  ];
}
```

网关在运行时通过 `DescriptorManager` 反查已加载描述符，识别带注解的字段，完全类型安全，无需运行时路径解析。

### 16.4 字段路径配置语法（Tier 2）

不使用完整 JMESPath（引入额外依赖且对管理员过于复杂），而是采用网关自行实现的**简单路径 + 条件过滤**语法，约 150 行 Rust 即可覆盖所有常见场景：

```
语法规则:
  path     = segment ("." segment)*
  segment  = field_name ("[" filter? "]")?  
  filter   = field_name "=" value         // 简单等值条件
           | (无)                           // 取数组全部元素
  value    = 单引号或无引号字符串

示例:
  messages[role=user].content   <- messages 数组中 role==user 的 content 字段
  messages[].content            <- messages 数组所有元素的 content 字段
  data.messages[role=user].text <- 嵌套一层后的数组
  prompt                        <- 顶层直接字段
  choices[0].message.content    <- 下标索引（响应解析用）
```

在 `ServiceAiGuardConfig` 中新增 `body_map` 字段（对应 proto 字段 22/23）：

```rust
/// 字段路径映射（Tier 2，管理员在服务编辑页配置）。
/// 空字符串 = 不使用该路径，由下一层策略兜底。
pub struct AiBodyFieldMap {
    /// 消息数组路径，例如 "messages"
    pub messages_path: String,
    /// 消息内角色字段名，例如 "role"
    pub role_field: String,
    /// 消息内内容字段名，例如 "content"
    pub content_field: String,
    /// 用于分类的角色值，例如 "user"；空 = 取全部
    pub user_role_value: String,
    /// 单一 prompt 字段路径，例如 "prompt"
    pub prompt_path: String,
    /// 模型名称路径，例如 "model"
    pub model_path: String,
    /// max_tokens 路径，例如 "max_tokens"
    pub max_tokens_path: String,
}
```

对应 proto 扩展（追加到 `ServiceAiGuardConfig`）：

```protobuf
// 字段路径映射（Tier 2 提取策略；不配置时回退到启发式兜底）
message AiBodyFieldMap {
  string messages_path   = 1;   // 例: "messages"
  string role_field      = 2;   // 例: "role"
  string content_field   = 3;   // 例: "content"
  string user_role_value = 4;   // 例: "user"  (空 = 全部)
  string prompt_path     = 5;   // 例: "prompt"
  string model_path      = 6;   // 例: "model"
  string max_tokens_path = 7;   // 例: "max_tokens"
}
// 在 ServiceAiGuardConfig 末尾追加：
//   AiBodyFieldMap body_map = 22;
```

### 16.5 `AiBodyInspector` Rust trait 设计

```rust
/// 从请求体 JSON 中提取 AI 相关字段的抽象层。
/// 三种实现各对应一个提取层级，由 AiGuardMiddleware 在初始化时按优先级选择。
pub trait AiBodyInspector: Send + Sync {
    /// 解析 body bytes，返回 AiRequestEnvelope。
    /// 若无法提取则返回 None（交由上层决定放行还是拒绝）。
    fn extract(&self, body: &[u8]) -> Option<AiRequestEnvelope>;

    /// 对 AiRequestEnvelope 做上下文截断后，重新序列化回 JSON bytes。
    fn reserialize(&self, body: &[u8], envelope: &AiRequestEnvelope) -> Vec<u8>;
}

/// Tier 1: 从 proto descriptor 的 FieldOptions 注解推导路径
pub struct ProtoOptionsInspector { ... }

/// Tier 2: 使用管理员配置的字段路径表达式
pub struct FieldPathInspector {
    map: AiBodyFieldMap,
}

/// Tier 3: 按启发式规则尝试常见字段名
pub struct HeuristicInspector;

/// 工厂函数：按优先级构造合适的 Inspector
pub fn build_inspector(
    service_name: &str,
    descriptor_manager: &DescriptorManager,
    body_map: Option<&AiBodyFieldMap>,
) -> Arc<dyn AiBodyInspector> {
    // 1. 尝试从 descriptor 读取 ai_guard 注解
    if let Some(inspector) = ProtoOptionsInspector::from_descriptor(service_name, descriptor_manager) {
        return Arc::new(inspector);
    }
    // 2. 使用管理员配置的字段路径
    if let Some(map) = body_map {
        if map.has_any_path() {
            return Arc::new(FieldPathInspector::new(map.clone()));
        }
    }
    // 3. 兜底启发式
    Arc::new(HeuristicInspector)
}
```

### 16.6 各层覆盖场景对比

| 场景 | 推荐层级 | 说明 |
|------|----------|------|
| 内部 gRPC 服务，有完整 .proto 描述符 | **Tier 1** proto options | 字段语义由 proto 定义，零运行时配置 |
| 第三方 HTTP JSON API，字段结构已知 | **Tier 2** 字段路径配置 | 管理员在服务编辑页填写路径表达式 |
| 透明代理，不知道下游请求格式 | **Tier 3** 启发式 | 自动识别 messages/prompt/input，失败时 observe 放行 |
| OpenAI / Anthropic 标准格式 | **Tier 3** 启发式 | 无需任何配置，开箱即用 |

> **关键决策**：不引入完整 JMESPath 库（`jmespath-rs` 等），原因是路径语法对运维人员过于复杂，且实际所需能力只是数组过滤+字段提取，自实现约 150 行即可覆盖。如果未来需要支持更复杂的提取逻辑（如嵌套条件、函数调用），再考虑引入 JMESPath。

### 17.1 设计原则

AI Guard **不提供全局配置页面**。管理员在以下三个已有入口对**每个服务单独配置**，做到一服务一策略：

| 入口页面 | 文件 | 场景 |
|----------|------|------|
| 服务注册 | `Registry.tsx` | 新服务首次注册时配置 |
| 服务编辑 | `Management.tsx` | 修改已注册服务的 AI Guard 策略 |
| 服务详情 | `Discovery.tsx` | 只读查看当前生效配置 |

`ServiceSecurityFormSection` 组件通过 `baseName` prop 嵌入上述三个页面的 `<Form>` 中，AI Guard 卡片作为其中一个 `<Card>` 追加在 Turnstile 之后。

### 17.2 表单字段设计

新增 `ai_guard` 命名空间下的字段，与现有 `cors` / `risk` / `turnstile` 并列：

```tsx
// ServiceSecurityFormSection.tsx 中新增 AI Guard Card
<Card size="small" title="AI Guard（防滥用）" style={{ marginBottom: 16 }}>

  {/* 基础开关 */}
  <Form.Item name={withBase(baseName, 'ai_guard', 'enabled')} label="启用 AI Guard" valuePropName="checked">
    <Switch checkedChildren="开" unCheckedChildren="关" />
  </Form.Item>
  <Form.Item name={withBase(baseName, 'ai_guard', 'mode')} label="运行模式">
    <Select options={[
      { label: '观察（只记录不拦截）', value: 'observe' },
      { label: '拦截（enforce）', value: 'enforce' },
    ]} />
  </Form.Item>
  <Form.Item name={withBase(baseName, 'ai_guard', 'include_paths_text')} label="生效路径前缀">
    <TextArea rows={2} placeholder={'/v1/chat/completions\n/api/ai/'} />
  </Form.Item>

  {/* 请求体 & Token 限制 */}
  <Row gutter={16}>
    <Col span={8}>
      <Form.Item name={withBase(baseName, 'ai_guard', 'request_body_max_bytes')} label="请求体上限 (bytes)">
        <InputNumber min={0} style={{ width: '100%' }} placeholder="0 = 不限" />
      </Form.Item>
    </Col>
    <Col span={8}>
      <Form.Item name={withBase(baseName, 'ai_guard', 'max_input_tokens')} label="最大输入 tokens">
        <InputNumber min={0} style={{ width: '100%' }} placeholder="0 = 不限" />
      </Form.Item>
    </Col>
    <Col span={8}>
      <Form.Item name={withBase(baseName, 'ai_guard', 'max_output_tokens')} label="最大输出 tokens 预算">
        <InputNumber min={0} style={{ width: '100%' }} placeholder="0 = 不限" />
      </Form.Item>
    </Col>
  </Row>

  {/* 上下文控制 */}
  <Row gutter={16}>
    <Col span={12}>
      <Form.Item name={withBase(baseName, 'ai_guard', 'max_context_tokens')} label="上下文最大 tokens">
        <InputNumber min={0} style={{ width: '100%' }} placeholder="0 = 不限" />
      </Form.Item>
    </Col>
    <Col span={12}>
      <Form.Item name={withBase(baseName, 'ai_guard', 'history_policy')} label="历史截断策略">
        <Select options={[
          { label: '保留最近 N 条消息', value: 'truncate_last_n' },
          { label: '按 token 数截断', value: 'truncate_to_max_tokens' },
        ]} />
      </Form.Item>
    </Col>
  </Row>

  {/* 配额窗口选择器 */}
  <Form.Item
    name={withBase(baseName, 'ai_guard', 'quota_window_secs')}
    label="配额刷新窗口"
    tooltip="窗口结束后 token 和请求计数自动清零；切换窗口长度时旧配额记录随 TTL 自然过期"
  >
    <Select
      allowClear
      placeholder="0 = 沿用全局（默认每日重置）"
      options={[
        { label: '每小时重置 (1h)',    value: 3600 },
        { label: '每 5 小时重置 (5h)', value: 18000 },
        { label: '每 12 小时重置 (12h)', value: 43200 },
        { label: '每日重置 (24h)',     value: 86400 },
      ]}
    />
  </Form.Item>
  <Form.Item
    name={withBase(baseName, 'ai_guard', 'quota_window_secs_custom')}
    label="自定义窗口（秒）"
    tooltip="不在上方预设中时可直接填写秒数，例如 7200 = 2小时"
  >
    <InputNumber min={60} max={604800} style={{ width: '100%' }} placeholder="留空则使用上方预设值" />
  </Form.Item>

  {/* 配额数值 */}
  <Row gutter={16}>
    <Col span={8}>
      <Form.Item name={withBase(baseName, 'ai_guard', 'daily_token_quota')} label="每用户每窗口 token 配额">
        <InputNumber min={0} style={{ width: '100%' }} placeholder="0 = 沿用全局" />
      </Form.Item>
    </Col>
    <Col span={8}>
      <Form.Item name={withBase(baseName, 'ai_guard', 'daily_request_quota')} label="每用户每窗口请求次数">
        <InputNumber min={0} style={{ width: '100%' }} placeholder="0 = 沿用全局" />
      </Form.Item>
    </Col>
    <Col span={8}>
      <Form.Item name={withBase(baseName, 'ai_guard', 'minute_request_quota')} label="每用户分钟请求次数">
        <InputNumber min={0} style={{ width: '100%' }} placeholder="0 = 沿用全局" />
      </Form.Item>
    </Col>
  </Row>

  {/* 话题过滤 */}
  <Form.Item name={withBase(baseName, 'ai_guard', 'allow_free_chat')} label="允许自由聊天" valuePropName="checked">
    <Switch checkedChildren="允许" unCheckedChildren="禁止" />
  </Form.Item>
  <Row gutter={16}>
    <Col span={12}>
      <Form.Item name={withBase(baseName, 'ai_guard', 'allowed_topics_text')} label="允许话题关键词（白名单）">
        <TextArea rows={3} placeholder={'每行一个关键词\nSQL\ndatabase'} />
      </Form.Item>
    </Col>
    <Col span={12}>
      <Form.Item name={withBase(baseName, 'ai_guard', 'deny_keywords_text')} label="拒绝关键词（黑名单）">
        <TextArea rows={3} placeholder={'每行一个关键词\njailbreak\nroleplay'} />
      </Form.Item>
    </Col>
  </Row>

  {/* 意图分类器 */}
  <Form.Item name={withBase(baseName, 'ai_guard', 'classifier_type')} label="分类器类型">
    <Select options={[
      { label: '规则（无外部调用）', value: 'rule' },
      { label: 'LLM + 规则兜底', value: 'llm' },
    ]} />
  </Form.Item>
  <Form.Item name={withBase(baseName, 'ai_guard', 'llm_model')} label="LLM 模型（留空沿用全局）">
    <Input placeholder="gpt-4o-mini / gemini-1.5-flash / qwen-turbo" />
  </Form.Item>
  <Form.Item name={withBase(baseName, 'ai_guard', 'llm_endpoint')} label="LLM 端点（留空沿用全局）">
    <Input placeholder="https://api.openai.com/v1/chat/completions" />
  </Form.Item>

  {/* 业务意图 prompt 构建 */}
  <Form.Item
    name={withBase(baseName, 'ai_guard', 'business_description')}
    label="业务描述"
    tooltip="服务用途简介，llm_system_prompt 为空时自动注入为 LLM 分类器的业务上下文"
  >
    <Input placeholder="A coding assistant that helps users write and debug code." />
  </Form.Item>
  <Row gutter={16}>
    <Col span={12}>
      <Form.Item
        name={withBase(baseName, 'ai_guard', 'valid_intent_examples_text')}
        label="有效请求示例（正例）"
        tooltip="每行一个，用于 few-shot 意图分类提示词构建"
      >
        <TextArea rows={3} placeholder={'每行一个\nHow do I write a SQL join?\nFix this Python error'} />
      </Form.Item>
    </Col>
    <Col span={12}>
      <Form.Item
        name={withBase(baseName, 'ai_guard', 'invalid_intent_examples_text')}
        label="无效请求示例（负例）"
        tooltip="每行一个，用于 few-shot 意图分类提示词构建"
      >
        <TextArea rows={3} placeholder={'每行一个\nWrite me a poem\nWhat is the weather today?'} />
      </Form.Item>
    </Col>
  </Row>
  <Form.Item
    name={withBase(baseName, 'ai_guard', 'llm_system_prompt')}
    label="完整自定义 Prompt（可选）"
    tooltip="填写后覆盖业务描述和示例，直接作为 LLM system prompt 使用"
  >
    <TextArea
      rows={4}
      placeholder={`You are a classifier for a SQL assistant.\nOnly allow SQL, database, and data analysis questions.\nRespond ONLY with JSON: {"allowed": true|false, "reason": "...", "confidence": 0.0-1.0}`}
    />
  </Form.Item>

  {/* 审计 */}
  <Form.Item name={withBase(baseName, 'ai_guard', 'enable_audit')} label="启用审计日志" valuePropName="checked">
    <Switch checkedChildren="开" unCheckedChildren="关" />
  </Form.Item>

  {/* =============== 接口级配置覆盖 (v2.0 新增) =============== */}
  <Divider orientation="left">接口级配置覆盖</Divider>
  <Form.List name={withBase(baseName, 'ai_guard', 'endpoint_overrides')}>
    {(fields, { add, remove }) => (
      <>
        {fields.map(({ key, name, ...rest }) => (
          <Card
            key={key}
            size="small"
            title={`端点 #${name + 1}`}
            extra={<Button type="link" danger onClick={() => remove(name)}>删除</Button>}
            style={{ marginBottom: 12 }}
          >
            <Row gutter={16}>
              <Col span={8}>
                <Form.Item
                  {...rest}
                  name={[name, 'endpoint_id']}
                  label="端点标识 (endpoint_id)"
                  rules={[{ required: true, message: '必填' }]}
                >
                  <Input placeholder="chat-gpt4 / embedding / models-meta" />
                </Form.Item>
              </Col>
              <Col span={8}>
                <Form.Item {...rest} name={[name, 'exact_paths_text']} label="精确路径">
                  <TextArea rows={2} placeholder={'/v1/chat/completions\n/stew.api.v1.Chat/Send'} />
                </Form.Item>
              </Col>
              <Col span={8}>
                <Form.Item {...rest} name={[name, 'prefix_paths_text']} label="前缀路径">
                  <TextArea rows={2} placeholder={'/stew.api.v1.Chat\n/v1/embeddings'} />
                </Form.Item>
              </Col>
            </Row>
            <Row gutter={16}>
              <Col span={6}>
                <Form.Item {...rest} name={[name, 'disabled']} label="禁用" valuePropName="checked">
                  <Switch checkedChildren="禁用" unCheckedChildren="启用" />
                </Form.Item>
              </Col>
              <Col span={6}>
                <Form.Item {...rest} name={[name, 'mode']} label="运行模式">
                  <Select allowClear placeholder="继承服务级" options={[
                    { label: '观察', value: 'observe' },
                    { label: '拦截', value: 'enforce' },
                  ]} />
                </Form.Item>
              </Col>
              <Col span={6}>
                <Form.Item {...rest} name={[name, 'classifier_type']} label="分类器">
                  <Select allowClear placeholder="继承服务级" options={[
                    { label: '规则', value: 'rule' },
                    { label: 'LLM', value: 'llm' },
                  ]} />
                </Form.Item>
              </Col>
              <Col span={6}>
                <Form.Item {...rest} name={[name, 'minute_request_quota']} label="每分钟请求数">
                  <InputNumber min={0} style={{ width: '100%' }} placeholder="0=继承" />
                </Form.Item>
              </Col>
            </Row>
            {/* 可折叠的详细覆盖字段 */}
            <Collapse ghost>
              <Collapse.Panel header="配额与 Token 限制" key="quota">
                <Row gutter={16}>
                  <Col span={8}>
                    <Form.Item {...rest} name={[name, 'daily_token_quota']} label="窗口 token 配额">
                      <InputNumber min={0} style={{ width: '100%' }} placeholder="0=继承" />
                    </Form.Item>
                  </Col>
                  <Col span={8}>
                    <Form.Item {...rest} name={[name, 'daily_request_quota']} label="窗口请求配额">
                      <InputNumber min={0} style={{ width: '100%' }} placeholder="0=继承" />
                    </Form.Item>
                  </Col>
                  <Col span={8}>
                    <Form.Item {...rest} name={[name, 'max_input_tokens']} label="最大输入 tokens">
                      <InputNumber min={0} style={{ width: '100%' }} placeholder="0=继承" />
                    </Form.Item>
                  </Col>
                </Row>
                <Row gutter={16}>
                  <Col span={8}>
                    <Form.Item {...rest} name={[name, 'max_output_tokens']} label="最大输出 tokens">
                      <InputNumber min={0} style={{ width: '100%' }} placeholder="0=继承" />
                    </Form.Item>
                  </Col>
                  <Col span={8}>
                    <Form.Item {...rest} name={[name, 'quota_window_secs']} label="窗口(秒)">
                      <InputNumber min={0} style={{ width: '100%' }} placeholder="0=继承" />
                    </Form.Item>
                  </Col>
                  <Col span={8}>
                    <Form.Item {...rest} name={[name, 'request_body_max_bytes']} label="请求体上限(bytes)">
                      <InputNumber min={0} style={{ width: '100%' }} placeholder="0=继承" />
                    </Form.Item>
                  </Col>
                </Row>
              </Collapse.Panel>
              <Collapse.Panel header="意图分类与关键词" key="classify">
                <Form.Item {...rest} name={[name, 'business_description']} label="业务描述">
                  <Input placeholder="继承服务级" />
                </Form.Item>
                <Form.Item {...rest} name={[name, 'llm_system_prompt']} label="自定义 Prompt">
                  <TextArea rows={2} placeholder="继承服务级" />
                </Form.Item>
                <Row gutter={16}>
                  <Col span={12}>
                    <Form.Item {...rest} name={[name, 'deny_keywords_text']} label="拒绝关键词">
                      <TextArea rows={2} placeholder="空=继承服务级" />
                    </Form.Item>
                  </Col>
                  <Col span={12}>
                    <Form.Item {...rest} name={[name, 'allowed_topics_text']} label="允许话题">
                      <TextArea rows={2} placeholder="空=继承服务级" />
                    </Form.Item>
                  </Col>
                </Row>
              </Collapse.Panel>
            </Collapse>
          </Card>
        ))}
        <Form.Item>
          <Button type="dashed" onClick={() => add()} block>
            + 添加接口级配置
          </Button>
        </Form.Item>
      </>
    )}
  </Form.List>

</Card>
```

### 17.3 securityConfig.ts 类型扩展

在 `ServiceSecurityFormValue` 接口中新增 `ai_guard` 字段：

```ts
export interface AiGuardEndpointFormValue {
    endpoint_id: string;
    exact_paths_text?: string;        // 换行分隔，映射 exact_paths[]
    prefix_paths_text?: string;       // 换行分隔，映射 prefix_paths[]
    disabled?: boolean;
    mode?: string;
    request_body_max_bytes?: number;
    max_input_tokens?: number;
    max_output_tokens?: number;
    max_context_tokens?: number;
    history_policy?: string;
    daily_token_quota?: number;
    daily_request_quota?: number;
    minute_request_quota?: number;
    quota_window_secs?: number;
    allow_free_chat?: boolean;
    allowed_topics_text?: string;
    deny_keywords_text?: string;
    classifier_type?: string;
    llm_endpoint?: string;
    llm_model?: string;
    llm_system_prompt?: string;
    business_description?: string;
    valid_intent_examples_text?: string;
    invalid_intent_examples_text?: string;
    enable_audit?: boolean;
}

export interface AiGuardFormValue {
    enabled?: boolean;
    mode?: string;                    // 'observe' | 'enforce'
    include_paths_text?: string;      // 换行分隔，映射 include_paths[]
    request_body_max_bytes?: number;
    max_input_tokens?: number;
    max_output_tokens?: number;
    max_context_tokens?: number;
    history_policy?: string;
    /// 配额刷新窗口秒数。预设: 3600 | 18000 | 43200 | 86400；自定义时填 quota_window_secs_custom。
    /// 两字段在 buildSecurityConfigFromForm 中合并: custom 非零时覆盖 quota_window_secs。
    quota_window_secs?: number;
    quota_window_secs_custom?: number;
    daily_token_quota?: number;
    daily_request_quota?: number;
    minute_request_quota?: number;
    allow_free_chat?: boolean;
    allowed_topics_text?: string;     // 换行分隔，映射 allowed_topics[]
    deny_keywords_text?: string;      // 换行分隔，映射 deny_keywords[]
    classifier_type?: string;         // 'rule' | 'llm'
    llm_endpoint?: string;
    llm_model?: string;
    llm_system_prompt?: string;       // 完整自定义 prompt（优先级最高）
    business_description?: string;    // 服务用途描述（llm_system_prompt 为空时生效）
    valid_intent_examples_text?: string;   // 换行分隔，映射 valid_intent_examples[]
    invalid_intent_examples_text?: string; // 换行分隔，映射 invalid_intent_examples[]
    enable_audit?: boolean;
    endpoint_overrides?: AiGuardEndpointFormValue[];  // v2.0 新增
}

export interface ServiceSecurityFormValue {
    cors?: { /* 现有字段 */ };
    risk?: { /* 现有字段 */ };
    turnstile?: { /* 现有字段 */ };
    ai_guard?: AiGuardFormValue;      // 新增
}
```

`buildSecurityConfigFromForm` / `extractSecurityConfigFormValue` 中按现有 turnstile 转换模式处理 `ai_guard`，`_text` 后缀字段通过 `\n` 分割转为数组，反向合并同理。

`endpoint_overrides` 数组中的每个元素同样需处理 `_text` 后缀字段转换（`exact_paths_text` -> `exact_paths[]`，`prefix_paths_text` -> `prefix_paths[]` 等），并在前端校验 `endpoint_id` 在同一服务内唯一。

### 17.4 Discovery.tsx 服务列表展示

在服务列表的标签列（与风险、Turnstile 徽标并列）中新增 AI Guard 标识：

```ts
// Discovery.tsx badge 逻辑（现有模式）
if (mw.ai_guard_enabled || mw.ai_guard?.enabled) {
    tags.push(<Tag color="purple">AI Guard</Tag>);
    // 展示已配置的接口级覆盖数量
    const epCount = mw.ai_guard?.endpoint_overrides?.length ?? 0;
    if (epCount > 0) {
        tags.push(<Tag color="geekblue">{epCount} 接口配置</Tag>);
    }
}
```

在服务详情展开区域，列出各 endpoint override 的标识、匹配路径及关键覆盖字段：

```tsx
{mw.ai_guard?.endpoint_overrides?.map((ep) => (
  <Descriptions key={ep.endpoint_id} title={`端点: ${ep.endpoint_id}`}
    column={3} size="small" bordered
  >
    <Descriptions.Item label="精确路径">{ep.exact_paths?.join(', ') || '-'}</Descriptions.Item>
    <Descriptions.Item label="前缀路径">{ep.prefix_paths?.join(', ') || '-'}</Descriptions.Item>
    <Descriptions.Item label="状态">{ep.disabled ? '已禁用' : '启用'}</Descriptions.Item>
    <Descriptions.Item label="模式">{ep.mode || '继承'}</Descriptions.Item>
    <Descriptions.Item label="Token 配额">{ep.daily_token_quota || '继承'}</Descriptions.Item>
    <Descriptions.Item label="请求配额">{ep.daily_request_quota || '继承'}</Descriptions.Item>
  </Descriptions>
))}
```

---

## 18. 相关文件索引

| 文件 | 作用 |
|------|------|
| [src/app/middleware_configurator.rs](../src/app/middleware_configurator.rs) | 中间件链装配，AiGuard 插入点 |
| [src/core/middleware.rs](../src/core/middleware.rs) | 真正使用的 `MiddlewareError` 定义 |
| [src/middleware/rate_limit.rs](../src/middleware/rate_limit.rs) | Redis 计数模式参考 |
| [src/middleware/risk_assessment.rs](../src/middleware/risk_assessment.rs) | x-risk-action 注入与 observe/enforce 模式参考 |
| [src/core/service_security_config.rs](../src/core/service_security_config.rs) | 服务级配置转换层参考 |
| [src/core/app_config.rs](../src/core/app_config.rs) | 全局配置结构参考 |
| [proto/service_discovery.proto](../proto/service_discovery.proto) | 协议扩展点 (field 40/41) |
| [web/src/pages/Services/securityConfig.ts](../web/src/pages/Services/securityConfig.ts) | 前端表单值 <-> proto 映射，需扩展 `AiGuardFormValue` |
| [web/src/pages/Services/ServiceSecurityFormSection.tsx](../web/src/pages/Services/ServiceSecurityFormSection.tsx) | 服务级安全配置表单，新增 AI Guard Card |
| [web/src/pages/Services/Registry.tsx](../web/src/pages/Services/Registry.tsx) | 服务注册入口，嵌入 `ServiceSecurityFormSection` |
| [web/src/pages/Services/Management.tsx](../web/src/pages/Services/Management.tsx) | 服务编辑入口，嵌入 `ServiceSecurityFormSection` |
| [web/src/pages/Services/Discovery.tsx](../web/src/pages/Services/Discovery.tsx) | 服务列表，新增 AI Guard badge 展示 |
