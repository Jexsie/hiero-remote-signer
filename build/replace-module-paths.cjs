// Ensure that all local imports go from .js to .cjs in the CommonJS build.
// https://github.com/liady/babel-plugin-module-rewrite
module.exports = function replaceImport(originalPath) {
    if (originalPath.startsWith(".") && originalPath.endsWith(".js")) {
        return originalPath.replace(/\.js$/, ".cjs");
    }
    return originalPath;
};
