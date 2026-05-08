// Re-exports from `@beyond.dev/openapi-react`, scoped to the React SDK. The
// camelCase contract this SDK exposes lives in `./types.ts` (generated from
// the OpenAPI spec by `scripts/generate-react-types.mjs`); the runtime is the
// library's plain pass-through — the proxy in front of the auth server
// handles the snake_case ↔ camelCase translation in both directions, so the
// SDK doesn't transform anything itself.
export {
  type CachedResponse,
  type ClientOptions,
  createClient,
  type Data,
  type ErrorData,
  ErrorResponse,
  type Input,
  type LoadablePaths,
  type LoadOptions,
  type LoadResult,
  type Output,
  type PathMatcher,
  type TypedResponse,
  type UseActionOptions,
  type UseActionResult,
  type UseInlineLoaderOptions,
  type UseInlineLoaderResult,
  type UseLoaderOptions,
  type UseLoaderResult,
} from "@beyond.dev/openapi-react";
