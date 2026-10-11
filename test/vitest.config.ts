import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: ["test/unit/**/*.test.ts"],
        environment: "node",
        coverage: {
            provider: "v8",
            // `json-summary` and `json` feed coverage reporting in CI, `lcov`
            // is kept for local tools and `text-summary` for the terminal.
            reporter: ["text-summary", "json-summary", "json", "lcov"],
            // Emit reports even when tests fail.
            reportOnFailure: true,
            reportsDirectory: "./coverage/node",
            include: ["src/**/*.ts"],
            exclude: ["src/**/index.ts", "src/**/*.d.ts", "src/types/**"],
            // Fail the unit-test run if any metric drops below 90%.
            // The unit config is the canonical coverage surface.
            thresholds: {
                lines: 90,
                statements: 90,
                functions: 90,
                branches: 90,
            },
        },
    },
});
