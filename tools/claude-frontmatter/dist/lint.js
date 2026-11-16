#!/usr/bin/env node
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
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const yaml = __importStar(require("js-yaml"));
const child_process_1 = require("child_process");
const parser_1 = require("./parser");
const REQUIRED_FIELDS = ["id", "title", "date"];
const ROOT_CONFIG = ".claude/frontmatter.yaml";
function loadRootConfig(root) {
    const configFile = path.join(root, ROOT_CONFIG);
    if (!fs.existsSync(configFile))
        return {};
    try {
        const raw = yaml.load(fs.readFileSync(configFile, "utf-8"));
        return (raw && typeof raw === "object") ? raw : {};
    }
    catch {
        return {};
    }
}
function matchesScope(file, patterns) {
    const f = file.replace(/\\/g, "/");
    return patterns.some(pattern => {
        const p = pattern.replace(/\\/g, "/");
        if (p.endsWith("/**")) {
            const prefix = p.slice(0, -3);
            return f === prefix || f.startsWith(prefix + "/");
        }
        const regex = new RegExp("^" + p
            .replace(/[.+^${}()|[\]\\]/g, "\\$&")
            .replace(/\*\*/g, ".*")
            .replace(/\*/g, "[^/]*")
            + "$");
        return regex.test(f);
    });
}
function findGitRoot(start) {
    try {
        const out = (0, child_process_1.execFileSync)("git", ["-C", start, "rev-parse", "--show-toplevel"], {
            encoding: "utf-8",
            stdio: ["ignore", "pipe", "ignore"],
        });
        return out.trim() || null;
    }
    catch {
        return null;
    }
}
function getSessionFiles(cwd) {
    try {
        const out = (0, child_process_1.execSync)("git diff --name-only HEAD", { encoding: "utf-8", cwd });
        return out.trim().split("\n").filter(f => f.endsWith(".md") && f.trim() !== "");
    }
    catch {
        return [];
    }
}
function getAllIds(root) {
    const ids = new Set();
    for (const file of (0, parser_1.walkMarkdown)(root)) {
        const doc = (0, parser_1.parseFrontmatter)(file);
        if (doc)
            ids.add(doc.id);
    }
    return ids;
}
function parseArgs(argv) {
    let session = false;
    let root;
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === "--session") {
            session = true;
            continue;
        }
        if (a.startsWith("--root=")) {
            root = a.slice("--root=".length);
            continue;
        }
        if (a === "--root" && i + 1 < argv.length) {
            root = argv[++i];
            continue;
        }
    }
    return { session, root };
}
function lint(files, root, idScope, taxonomy) {
    const violations = [];
    const allIds = getAllIds(idScope);
    const tagSet = taxonomy ? new Set(taxonomy.tags) : null;
    for (const file of files) {
        if (!fs.existsSync(file))
            continue;
        const cfg = (0, parser_1.resolveConfig)(root, file);
        if (!cfg.prefix) {
            violations.push({
                file: path.relative(root, file),
                message: "No frontmatter.yaml config found — run /new-doc to initialize document ID config",
            });
        }
        const doc = (0, parser_1.parseFrontmatter)(file);
        if (!doc) {
            violations.push({ file, message: "Missing or invalid YAML frontmatter" });
            continue;
        }
        for (const field of REQUIRED_FIELDS) {
            if (!doc[field]) {
                violations.push({ file, message: `Missing required field: ${field}` });
            }
        }
        for (const rel of doc.related) {
            if (!allIds.has(rel.id)) {
                violations.push({ file, message: `Broken related link: ${rel.id} not found` });
            }
        }
        if (tagSet && taxonomy) {
            for (const tag of doc.tags) {
                if (tagSet.has(tag))
                    continue;
                const canonical = taxonomy.synonyms[tag];
                if (canonical !== undefined) {
                    violations.push({
                        file: path.relative(root, file),
                        message: `Tag '${tag}' is a synonym for '${canonical}'`,
                    });
                }
                else {
                    violations.push({
                        file: path.relative(root, file),
                        message: `Unknown tag: ${tag}`,
                    });
                }
            }
        }
    }
    return violations;
}
function realpath(p) {
    try {
        return fs.realpathSync(p);
    }
    catch {
        return p;
    }
}
const { session, root: rootArg } = parseArgs(process.argv.slice(2));
const root = realpath(path.resolve(rootArg ?? "."));
const config = loadRootConfig(root);
const gitRoot = realpath(findGitRoot(root) ?? root);
// ID scope spans the whole repo so cross-module related links validate.
const idScope = gitRoot;
const taxonomy = (0, parser_1.loadTaxonomy)(root);
function inScope(relPath) {
    if (!config.scope || config.scope.length === 0)
        return true;
    return matchesScope(relPath, config.scope);
}
let files;
if (session) {
    // Session paths from `git diff` are relative to the git root.
    files = getSessionFiles(gitRoot)
        .filter(f => inScope(f))
        .map(f => path.join(gitRoot, f))
        .filter(f => f.startsWith(root + path.sep) || f === root || !rootArg);
}
else {
    files = (0, parser_1.walkMarkdown)(root).filter(abs => {
        const rel = path.relative(gitRoot, abs);
        return inScope(rel);
    });
}
if (files.length === 0) {
    process.exit(0);
}
const violations = lint(files, root, idScope, taxonomy);
if (violations.length === 0) {
    process.exit(0);
}
console.log("Frontmatter violations found — please fix before finishing:\n");
for (const v of violations) {
    console.log(`  ${v.file}`);
    console.log(`    → ${v.message}`);
}
console.log();
process.exit(1);
