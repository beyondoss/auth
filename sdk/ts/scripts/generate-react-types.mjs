// Generates the camelCase OpenAPI `paths` type that the React SDK consumes.
//
// The auth server's OpenAPI spec is snake_case (the server is Rust and we
// don't want to fight that), but the gateway in front of it accepts camelCase
// request bodies and emits camelCase responses. The React SDK only ever sees
// the camelCase wire format, so its `paths` type should match — anything else
// would force every hook caller to write snake_case keys that don't exist on
// the wire.
//
// Strategy: clone `openapi/v1.json`, camelize every schema property name
// (which only affects request and response body shapes — parameter names like
// `member_id` stay alone because they live in the URL/query string and the
// gateway doesn't rewrite those), then run `openapi-typescript` against the
// rewritten spec. The output lives at `src/react/types.ts` and is committed.
import { execSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
const specIn = resolve(dir, "../../../openapi/v1.json");
const out = resolve(dir, "../src/react/types.ts");

const CAMEL_RE = /_([a-z])/g;
function camelKey(key) {
  return key.replace(CAMEL_RE, (_, c) => c.toUpperCase());
}

// Walk the JSON Schema-like tree, rewriting `properties` keys (and the
// matching entries in `required`) to camelCase. Other shape keys we may
// recurse through include `items`, `additionalProperties`, `allOf`, `anyOf`,
// `oneOf`, and the `*Of` variants used by openapi-typescript.
function camelizeSchema(node) {
  if (node === null || typeof node !== "object") return node;
  if (Array.isArray(node)) return node.map(camelizeSchema);

  const out = {};
  for (const [k, v] of Object.entries(node)) {
    if (k === "properties" && v && typeof v === "object") {
      const rewritten = {};
      for (const [propKey, propSchema] of Object.entries(v)) {
        rewritten[camelKey(propKey)] = camelizeSchema(propSchema);
      }
      out[k] = rewritten;
    } else if (k === "required" && Array.isArray(v)) {
      out[k] = v.map((name) =>
        typeof name === "string" ? camelKey(name) : name
      );
    } else {
      out[k] = camelizeSchema(v);
    }
  }
  return out;
}

const spec = JSON.parse(readFileSync(specIn, "utf8"));
const camelizedSpec = camelizeSchema(spec);

const tmp = mkdtempSync(join(tmpdir(), "auth-react-spec-"));
const tmpSpec = join(tmp, "v1.camelized.json");
writeFileSync(tmpSpec, JSON.stringify(camelizedSpec));

try {
  execSync(
    `npx openapi-typescript ${tmpSpec} -o ${out} --empty-objects-unknown`,
    {
      stdio: "inherit",
    },
  );
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
