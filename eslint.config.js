import eslint from "@eslint/js";
import prettierConfig from "eslint-config-prettier";
import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";
import tseslint from "typescript-eslint";

export default defineConfig(
    globalIgnores(["**/dist/**", "**/node_modules/**", "**/coverage/**"]),

    eslint.configs.recommended,
    ...tseslint.configs.recommendedTypeChecked,
    // Turns off the stylistic rules that Prettier owns
    prettierConfig,

    {
        languageOptions: {
            globals: { ...globals.node },
            parserOptions: {
                // One project covering src, tests, the example and build
                // helpers, so every file gets type information.
                project: ["./tsconfig.eslint.json"],
                tsconfigRootDir: import.meta.dirname,
            },
        },
        rules: {
            // Deprecated SDK and library APIs are not allowed
            "@typescript-eslint/no-deprecated": "error",
            "@typescript-eslint/no-explicit-any": "error",
            "@typescript-eslint/no-unused-vars": [
                "error",
                { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
            ],
            "@typescript-eslint/consistent-type-imports": [
                "error",
                { prefer: "type-imports", fixStyle: "separate-type-imports" },
            ],
            // Receipts and parsed DER fields are checked before use
            "@typescript-eslint/no-non-null-assertion": "off",
        },
    },

    // Backend fakes implement async client APIs without awaiting anything
    {
        files: ["test/**/*.ts"],
        rules: { "@typescript-eslint/require-await": "off" },
    },

    // Plain JavaScript build helpers: no type-aware rules
    {
        files: ["**/*.js", "**/*.cjs"],
        extends: [tseslint.configs.disableTypeChecked],
    },
    {
        files: ["**/*.cjs"],
        languageOptions: { sourceType: "commonjs" },
    },
);
