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
const path = __importStar(require("path"));
const parser_1 = require("./parser");
function buildGraph(root) {
    const nodes = [];
    const edges = [];
    const seen = new Set();
    for (const file of (0, parser_1.walkMarkdown)(root)) {
        const doc = (0, parser_1.parseFrontmatter)(file);
        if (!doc || seen.has(doc.id))
            continue;
        seen.add(doc.id);
        nodes.push({ ...doc, file: path.relative(root, file) });
        for (const rel of doc.related) {
            edges.push({ from: doc.id, to: rel.id, reason: rel.reason ?? "" });
        }
    }
    return { nodes, edges };
}
function printSummary(graph) {
    const byId = Object.fromEntries(graph.nodes.map(n => [n.id, n]));
    console.log(`Knowledge Graph — ${graph.nodes.length} documents, ${graph.edges.length} links\n`);
    const byType = {};
    for (const n of graph.nodes) {
        const t = n.type ?? "other";
        (byType[t] ?? (byType[t] = [])).push(n);
    }
    for (const [type, docs] of Object.entries(byType).sort()) {
        console.log(`[${type}]`);
        for (const d of docs) {
            const status = d.status ? `  (${d.status})` : "";
            const tags = d.tags.length ? `  [${d.tags.join(", ")}]` : "";
            console.log(`  ${d.id}  ${d.title}${status}${tags}`);
            console.log(`    ${d.file}`);
        }
        console.log();
    }
    if (graph.edges.length) {
        console.log("Links");
        for (const e of graph.edges) {
            const src = byId[e.from]?.title ?? e.from;
            const dst = byId[e.to]?.title ?? e.to;
            const why = e.reason ? ` — ${e.reason}` : "";
            console.log(`  ${src}  →  ${dst}${why}`);
        }
        console.log();
    }
    const linked = new Set([...graph.edges.map(e => e.from), ...graph.edges.map(e => e.to)]);
    const orphans = graph.nodes.filter(n => !linked.has(n.id));
    if (orphans.length) {
        console.log("Orphans (no links)");
        orphans.forEach(o => console.log(`  ${o.id}  ${o.title}`));
        console.log();
    }
    const ids = new Set(graph.nodes.map(n => n.id));
    const broken = graph.edges.filter(e => !ids.has(e.to));
    if (broken.length) {
        console.log("Broken links");
        broken.forEach(b => console.log(`  ${b.from}  →  ${b.to}  (target not found)`));
    }
}
const args = process.argv.slice(2);
const summary = args.includes("--summary");
function parseRoot(argv) {
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a.startsWith("--root="))
            return a.slice("--root=".length);
        if (a === "--root" && i + 1 < argv.length)
            return argv[i + 1];
    }
    return argv.find(a => !a.startsWith("--"));
}
const root = path.resolve(parseRoot(args) ?? ".");
const graph = buildGraph(root);
if (summary) {
    printSummary(graph);
}
else {
    console.log(JSON.stringify(graph, null, 2));
}
