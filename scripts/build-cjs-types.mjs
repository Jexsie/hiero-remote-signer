// Copies every emitted `.d.ts` to a `.d.cts` twin so the CommonJS entry
// points get CommonJS-flavoured types. tsup cannot bundle declarations with
// TypeScript 7, which has no compiler API, so declarations come from `tsc`.
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const dist = new URL("../dist/", import.meta.url).pathname;

for (const entry of await readdir(dist, { recursive: true })) {
    if (!entry.endsWith(".d.ts")) continue;
    const source = await readFile(join(dist, entry), "utf8");
    const cts = source
        .replace(/(from\s+["']\.{1,2}\/[^"']*)\.js(["'])/g, "$1.cjs$2")
        .replace(/^\/\/# sourceMappingURL=.*$/m, "");
    await writeFile(join(dist, entry.replace(/\.d\.ts$/, ".d.cts")), cts);
}
