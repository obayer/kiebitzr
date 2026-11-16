"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveConfig = resolveConfig;
exports.loadTaxonomy = loadTaxonomy;
exports.parseFrontmatter = parseFrontmatter;
exports.walkMarkdown = walkMarkdown;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const yaml = __importStar(require("js-yaml"));
function loadConfigFile(filePath) {
    try {
        const raw = yaml.load(fs.readFileSync(filePath, "utf-8"));
        return (raw && typeof raw === "object") ? raw : {};
    }
    catch {
        return {};
    }
}
function resolveConfig(root, filePath) {
    const absRoot = path.resolve(root);
    let dir = path.resolve(path.dirname(filePath));
    while (true) {
        const direct = path.join(dir, "frontmatter.yaml");
        if (fs.existsSync(direct))
            return loadConfigFile(direct);
        const inClaude = path.join(dir, ".claude", "frontmatter.yaml");
        if (fs.existsSync(inClaude))
            return loadConfigFile(inClaude);
        if (dir === absRoot)
            break;
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return {};
}
function loadTaxonomy(startDir) {
    let dir = path.resolve(startDir);
    while (true) {
        for (const candidate of [
            path.join(dir, ".claude", "taxonomy.yaml"),
            path.join(dir, "taxonomy.yaml"),
        ]) {
            if (!fs.existsSync(candidate))
                continue;
            try {
                const raw = yaml.load(fs.readFileSync(candidate, "utf-8"));
                if (!raw || typeof raw !== "object")
                    return null;
                const r = raw;
                return {
                    tags: Array.isArray(r["tags"]) ? r["tags"].map(String) : [],
                    synonyms: (r["synonyms"] && typeof r["synonyms"] === "object" && !Array.isArray(r["synonyms"]))
                        ? Object.fromEntries(Object.entries(r["synonyms"]).map(([k, v]) => [k, String(v)]))
                        : {},
                };
            }
            catch {
                return null;
            }
        }
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return null;
}
function parseFrontmatter(filePath) {
    let content;
    try {
        content = fs.readFileSync(filePath, "utf-8");
    }
    catch {
        return null;
    }
    const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
    if (!match)
        return null;
    let fm;
    try {
        fm = yaml.load(match[1]);
    }
    catch {
        return null;
    }
    if (!fm || typeof fm !== "object")
        return null;
    const raw = fm;
    if (!raw["id"])
        return null;
    return {
        id: String(raw["id"]),
        title: String(raw["title"] ?? ""),
        type: raw["type"] ? String(raw["type"]) : undefined,
        status: raw["status"] ? String(raw["status"]) : undefined,
        date: raw["date"] ? String(raw["date"]) : undefined,
        tags: Array.isArray(raw["tags"]) ? raw["tags"].map(String) : [],
        related: Array.isArray(raw["related"])
            ? raw["related"]
                .filter((r) => !!r && typeof r === "object" && "id" in r)
                .map(r => ({ id: String(r["id"]), reason: r["reason"] ? String(r["reason"]) : "" }))
            : [],
        file: filePath,
    };
}
const DEFAULT_SKIP = ["node_modules", ".git", "template.md"];
function walkMarkdown(dir, skip = DEFAULT_SKIP) {
    const results = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (skip.includes(entry.name))
            continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            results.push(...walkMarkdown(full, skip));
        }
        else if (entry.isFile() && entry.name.endsWith(".md")) {
            results.push(full);
        }
    }
    return results;
}
