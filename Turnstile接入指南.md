# Cloudflare Turnstile 接入指南

Stew 网关内置了 Cloudflare Turnstile 服务端验证中间件，在请求到达后端业务服务之前统一完成人机验证，业务服务**无需**额外接入任何验证逻辑。

---

## 目录

- [工作原理](#工作原理)
- [网关配置](#网关配置)
- [环境变量](#环境变量)
- [中间件位置](#中间件位置)
- [前端接入](#前端接入)
  - [HTML 原生接入](#html-原生接入)
  - [React 接入](#react-接入)
  - [Vue 3 接入](#vue-3-接入)
- [业务后端接入](#业务后端接入)
- [Protobuf 选项控制（按接口跳过）](#按接口跳过验证)
- [响应格式](#响应格式)
- [测试凭据](#测试凭据)
- [常见问题](#常见问题)

---

## 工作原理

```
浏览器 / 客户端
  |
  | HTTP Header: cf-turnstile-response: <token>
  v
Stew 网关
  |-- TurnstileMiddleware
  |     1. 检查请求路径是否在白名单（skip_paths）
  |     2. 从 cf-turnstile-response 请求头提取 token
  |     3. POST https://challenges.cloudflare.com/turnstile/v0/siteverify
  |           { secret, response: token, remoteip }
  |     4. 校验 success / action / hostname（可选）
  |     5. 失败 → 503 Forbidden，终止请求
  |
  v
后续中间件（Auth → RateLimit → ...）
  v
后端 gRPC 业务服务（收到请求时，人机验证已通过）
```

**重要**：Secret Key 只在网关服务端使用，不暴露给客户端；业务服务收到请求时人机验证已经完成，无需重复校验。

---

## 网关配置

在 `config.yaml` 中添加 `turnstile` 节：

```yaml
turnstile:
  # 启用 Turnstile 验证
  enabled: true

  # Cloudflare 控制台获取的 Secret Key（也可通过环境变量 TURNSTILE_SECRET_KEY 设置）
  secret_key: "your-secret-key"

  # 客户端传递 token 使用的请求头（默认值与 Turnstile JS widget 一致，通常无需修改）
  token_header: "cf-turnstile-response"

  # 调用 Siteverify API 的超时时间（毫秒）
  timeout_ms: 5000

  # 不需要 Turnstile 验证的路径前缀（前缀匹配）
  skip_paths:
    - "/health"
    - "/metrics"
    - "/_openapi"

  # 可选：只接受指定 action 名称的 token，不一致时返回 403
  # 需要客户端 JS widget 配置 data-action 属性与此值相同
  # expected_action: "login"

  # 可选：只接受从指定 hostname 颁发的 token
  # expected_hostname: "example.com"
```

从 [Cloudflare 控制台](https://dash.cloudflare.com/) 进入 **Turnstile** 创建 Widget，获取：

- **Site Key**：前端 JS widget 使用。
- **Secret Key**：网关配置中使用，严禁写入前端代码。

---

## 环境变量

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `TURNSTILE_SECRET_KEY` | Secret Key（优先级高于 config.yaml） | `0x4AAAAAAA...` |

---

## 中间件位置

Turnstile 验证位于认证（Auth）中间件之前，保证只有通过人机验证的请求才会进入认证流程：

```
RequestId → RequestIdSpan → ClientContext
  → TurnstileMiddleware     ← 人机验证
  → UnifiedAuth             ← 身份认证（JWT / API Key）
  → RateLimit
  → HttpToGrpcMetadata
  → Logging
  → 业务服务
```

---

## 前端接入

前端需要：
1. 在页面中嵌入 Turnstile JS Widget，获取 token。
2. 在 API 请求的 Header 中携带该 token。

### HTML 原生接入

```html
<!DOCTYPE html>
<html>
<head>
  <!-- 引入 Turnstile JS -->
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body>
  <form id="login-form">
    <input type="text" name="username" placeholder="用户名" />
    <input type="password" name="password" placeholder="密码" />

    <!-- Turnstile Widget：data-sitekey 填写控制台获取的 Site Key -->
    <div class="cf-turnstile"
         data-sitekey="your-site-key"
         data-action="login"
         data-callback="onTurnstileSuccess">
    </div>

    <button type="submit" id="submit-btn" disabled>登录</button>
  </form>

  <script>
    let turnstileToken = null;

    // token 就绪回调
    function onTurnstileSuccess(token) {
      turnstileToken = token;
      document.getElementById('submit-btn').disabled = false;
    }

    document.getElementById('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();

      if (!turnstileToken) {
        alert('请完成人机验证');
        return;
      }

      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          // 网关从此 Header 读取 token 进行验证
          'cf-turnstile-response': turnstileToken,
        },
        body: JSON.stringify({
          username: e.target.username.value,
          password: e.target.password.value,
        }),
      });

      if (!response.ok) {
        // 403 表示人机验证失败；401 表示身份认证失败
        const text = await response.text();
        alert('请求失败: ' + text);
        // token 已失效（单次使用），需重置 widget
        turnstile.reset();
        turnstileToken = null;
        document.getElementById('submit-btn').disabled = true;
      }
    });
  </script>
</body>
</html>
```

### React 接入

安装官方 React 封装包：

```bash
npm install @marsidev/react-turnstile
# 或
pnpm add @marsidev/react-turnstile
```

```tsx
import { useState, useRef } from 'react';
import { Turnstile } from '@marsidev/react-turnstile';

export function LoginForm() {
  const [token, setToken] = useState<string | null>(null);
  const turnstileRef = useRef(null);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    if (!token) {
      alert('请完成人机验证');
      return;
    }

    const form = e.currentTarget;
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'cf-turnstile-response': token,
      },
      body: JSON.stringify({
        username: (form.elements.namedItem('username') as HTMLInputElement).value,
        password: (form.elements.namedItem('password') as HTMLInputElement).value,
      }),
    });

    if (!res.ok) {
      // token 单次有效，验证失败后必须重置 widget
      turnstileRef.current?.reset();
      setToken(null);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input name="username" placeholder="用户名" />
      <input name="password" type="password" placeholder="密码" />

      <Turnstile
        ref={turnstileRef}
        siteKey="your-site-key"
        options={{ action: 'login' }}
        onSuccess={setToken}
        onExpire={() => setToken(null)}
        onError={() => setToken(null)}
      />

      <button type="submit" disabled={!token}>登录</button>
    </form>
  );
}
```

### Vue 3 接入

安装封装包：

```bash
pnpm add vue-turnstile
```

```vue
<template>
  <form @submit.prevent="handleSubmit">
    <input v-model="username" placeholder="用户名" />
    <input v-model="password" type="password" placeholder="密码" />

    <VueTurnstile
      site-key="your-site-key"
      :options="{ action: 'login' }"
      @success="token = $event"
      @expire="token = null"
      @error="token = null"
      ref="turnstileRef"
    />

    <button type="submit" :disabled="!token">登录</button>
  </form>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import VueTurnstile from 'vue-turnstile';

const username = ref('');
const password = ref('');
const token = ref<string | null>(null);
const turnstileRef = ref(null);

async function handleSubmit() {
  if (!token.value) return;

  const res = await fetch('/api/v1/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'cf-turnstile-response': token.value,
    },
    body: JSON.stringify({ username: username.value, password: password.value }),
  });

  if (!res.ok) {
    turnstileRef.value?.reset();
    token.value = null;
  }
}
</script>
```

### 移动端 / 原生客户端

移动端可通过嵌入 WebView 渲染 Turnstile Widget 页面，在 JS 回调中将 token 通过 bridge 传递给原生层，再随 API 请求发送至网关。

---

## 业务后端接入

**业务 gRPC 服务无需任何改动。**

Turnstile 验证在网关层完成，验证失败的请求会被直接拒绝，不会到达业务服务。验证通过的请求与普通请求完全一致，业务服务感知不到 Turnstile 的存在。

如果需要在业务层获知请求是否经过 Turnstile 验证，可在网关中间件中注入自定义 Header（扩展需求，默认不注入）。

---

## 按接口跳过验证

如果只有部分接口需要 Turnstile 验证（例如登录、注册接口需要，其他接口不需要），有两种方式：

### 方式一：通过 skip_paths 白名单（推荐）

在配置中将不需要验证的路径前缀加入白名单：

```yaml
turnstile:
  enabled: true
  skip_paths:
    - "/health"
    - "/metrics"
    - "/_openapi"
    - "/api/v1/internal"   # 内部接口不需要人机验证
```

### 方式二：只对特定路径启用（反向白名单）

如果绝大多数接口不需要验证，可将 `enabled` 设为 `false`，由前端手动在只需要验证的场景中携带 token，后端业务服务自行调用 Siteverify API 验证（此时网关不做统一验证）。

---

## 响应格式

| 场景 | HTTP 状态码 | 响应体 |
|------|-------------|--------|
| token 缺失 | `403 Forbidden` | `Turnstile verification token is required` |
| token 格式非法（超长） | `400 Bad Request` | `Turnstile token is malformed` |
| token 已过期或已使用 | `403 Forbidden` | `Turnstile verification failed: timeout-or-duplicate` |
| token 验证失败 | `403 Forbidden` | `Turnstile verification failed: <error-codes>` |
| action 不匹配 | `403 Forbidden` | `Turnstile action mismatch` |
| Siteverify 请求超时 | `500 Internal Server Error` | `Turnstile verification request failed: ...` |
| 验证通过 | 正常响应 | 后端业务返回值 |

前端应对 `403` 响应执行 `turnstile.reset()` 以刷新 widget，生成新 token 供用户重试。

---

## 测试凭据

Cloudflare 提供专用测试密钥，**仅用于开发和测试环境**，生产环境必须替换：

| 类型 | 值 | 行为 |
|------|----|------|
| Site Key（始终通过） | `1x00000000000000000000AA` | widget 始终返回有效 token |
| Site Key（始终失败） | `2x00000000000000000000AB` | widget 始终返回无效 token |
| Site Key（强制交互） | `3x00000000000000000000FF` | 强制显示交互式验证 |
| Secret Key（始终通过） | `1x0000000000000000000000000000000AA` | Siteverify 始终返回 success |
| Secret Key（始终失败） | `2x0000000000000000000000000000000AA` | Siteverify 始终返回失败 |

开发环境配置示例：

```yaml
turnstile:
  enabled: true
  secret_key: "1x0000000000000000000000000000000AA"
```

前端使用对应测试 Site Key：

```html
<div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>
```

---

## 常见问题

**Q: token 有效期多长？**
A: 5 分钟（300 秒）。超时后 Siteverify 返回 `timeout-or-duplicate`，网关返回 403，前端需重置 widget。

**Q: token 能复用吗？**
A: 不能。每个 token 只能验证一次，验证成功后即失效。用户重试必须获取新 token。

**Q: 网关验证失败会影响 Auth 中间件吗？**
A: 不会。Turnstile 位于 Auth 之前，验证失败直接返回 403，不会进入认证流程。

**Q: 内网服务间调用需要带 token 吗？**
A: 不需要，将内网接口路径加入 `skip_paths` 即可跳过验证。

**Q: HTTPS 是否必须？**
A: 生产环境强烈建议使用 HTTPS。Turnstile widget 在 HTTP 下也能工作，但 Secret Key 必须仅在后端（网关）使用。
