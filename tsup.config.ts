import { defineConfig } from "tsup";

export default defineConfig({
    entry: {
        index: "src/index.ts",
        "aws/index": "src/aws/index.ts",
    },
    format: ["esm", "cjs"],
    // Declarations are emitted by `tsc`; see scripts/build-cjs-types.mjs.
    dts: false,
    sourcemap: true,
    clean: true,
    target: "node20",
    // @noble/hashes v2 is ESM-only; bundle it so the CommonJS build can
    // `require()` this package on every supported Node version.
    noExternal: ["@noble/hashes"],
});
