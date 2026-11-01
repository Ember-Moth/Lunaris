# Lunaris Web

React + TypeScript + shadcn/ui + Vite。前端静态资源通过同目录的 `embed.go` 嵌入 Go 程序。

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm lint
pnpm dev
```

`pnpm build` 先从 `../api/openapi.yaml` 生成 `src/api/schema.d.ts`，再进行类型检查和静态构建。TypeScript 固定为 5.9.3，以兼容当前 OpenAPI 类型生成器的编译器 API。

开发服务器将 `/healthz` 与 `/api` 代理到 `http://127.0.0.1:9080`。业务 API 尚未实现；页面仅显示真实的健康检查结果，不提供虚假的节点操作。

`src/components/ui` 是通过 shadcn CLI 添加的组件源码，其 MIT 声明保留在根目录 `THIRD_PARTY_NOTICES.md`。其余项目代码采用 GPL-3.0-only。
