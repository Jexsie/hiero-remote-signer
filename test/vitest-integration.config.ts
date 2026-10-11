import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: ["test/integration/**/*.spec.ts"],
        testTimeout: 120000,
        hookTimeout: 120000,
        environment: "node",
        setupFiles: ["test/utils/setup-env.ts"],
        coverage: {
            provider: "v8",
            reporter: ["text-summary", "json-summary", "json", "lcov"],
            reportOnFailure: true,
            reportsDirectory: "./coverage/integration",
            include: ["src/**/*.ts"],
            exclude: ["src/**/index.ts", "src/**/*.d.ts", "src/types/**"],
        },
    },
});
