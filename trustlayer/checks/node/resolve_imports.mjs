/**
 * Resolves TypeScript/JavaScript import specifiers and named imports against the
 * repository's own installed node_modules. Verified against ts-morph 27.0.2.
 *
 * Emits JSON on stdout: {findings: [...]} or {unresolvable: "..."}.
 * A package present on disk but shipping no types is reported as `no-types`, never as
 * `not-installed` - the two look identical to the resolver and conflating them would be
 * a false positive.
 */

import { existsSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { Project } from "ts-morph";

const root = process.argv[2];
const MAX_RANKED_NAMES = 5;

function emit(payload) {
  process.stdout.write(JSON.stringify(payload));
  process.exit(0);
}

if (!root || !existsSync(root)) {
  emit({ unresolvable: `repository path not found: ${root}` });
}

if (!existsSync(join(root, "node_modules"))) {
  emit({
    unresolvable:
      `no node_modules in ${root}, so import specifiers cannot be resolved. ` +
      `Install dependencies first (npm install / pnpm install / yarn install).`,
    file: "package.json",
    line: 1,
  });
}

/** Package directory for a bare specifier: "@scope/a/b" -> "@scope/a", "a/b" -> "a". */
function packageDirName(specifier) {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

function installedVersion(pkg) {
  try {
    const manifest = join(root, "node_modules", pkg, "package.json");
    return JSON.parse(readFileSync(manifest, "utf8")).version ?? null;
  } catch {
    return null;
  }
}

/** Similarity in [0,1]; mirrors difflib.SequenceMatcher closely enough for ranking. */
function similarity(a, b) {
  a = a.toLowerCase();
  b = b.toLowerCase();
  if (a === b) return 1;
  const rows = a.length + 1;
  const cols = b.length + 1;
  const dist = Array.from({ length: rows }, (_, i) =>
    Array.from({ length: cols }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  for (let i = 1; i < rows; i += 1) {
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dist[i][j] = Math.min(dist[i - 1][j] + 1, dist[i][j - 1] + 1, dist[i - 1][j - 1] + cost);
    }
  }
  const maxLen = Math.max(a.length, b.length) || 1;
  return 1 - dist[a.length][b.length] / maxLen;
}

function rankSimilar(wanted, names) {
  return names
    .map((name) => [name, similarity(wanted, name)])
    .filter(([, score]) => score > 0.4)
    .sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]))
    .slice(0, MAX_RANKED_NAMES)
    .map(([name, score]) => `${name} (${score.toFixed(2)})`);
}

const tsconfig = join(root, "tsconfig.json");
const project = new Project({
  tsConfigFilePath: existsSync(tsconfig) ? tsconfig : undefined,
  skipAddingFilesFromTsConfig: !existsSync(tsconfig),
  compilerOptions: { allowJs: true, noEmit: true },
});

if (!existsSync(tsconfig)) {
  project.addSourceFilesAtPaths([
    join(root, "**/*.{ts,tsx,mts,cts,js,jsx,mjs,cjs}"),
    `!${join(root, "**/node_modules/**")}`,
    `!${join(root, "**/dist/**")}`,
  ]);
}

const findings = [];

for (const sourceFile of project.getSourceFiles()) {
  const filePath = sourceFile.getFilePath();
  if (filePath.includes("/node_modules/")) continue;
  const file = relative(root, filePath);

  for (const declaration of sourceFile.getImportDeclarations()) {
    const specifier = declaration.getModuleSpecifierValue();
    const line = declaration.getStartLineNumber();
    const target = declaration.getModuleSpecifierSourceFile();

    if (!target) {
      const isRelative = specifier.startsWith(".");
      if (isRelative) {
        findings.push({
          severity: "high",
          file,
          line,
          claim: `import from "${specifier}"`,
          verdict: "unresolved-import",
          evidence: [`"${specifier}" does not resolve to a file relative to ${file}`],
        });
        continue;
      }

      const pkg = packageDirName(specifier);
      const onDisk = existsSync(join(root, "node_modules", pkg));
      if (onDisk) {
        findings.push({
          severity: "low",
          file,
          line,
          claim: `import from "${specifier}"`,
          verdict: "no-types",
          evidence: [
            `node_modules/${pkg} exists (version ${installedVersion(pkg) ?? "unknown"}) but ships no type declarations`,
            "named imports cannot be verified for this package",
          ],
        });
      } else {
        findings.push({
          severity: "medium",
          file,
          line,
          claim: `import from "${specifier}"`,
          verdict: "not-installed",
          evidence: [`node_modules/${pkg} does not exist in ${relative(process.cwd(), root) || "."}`],
        });
      }
      continue;
    }

    const namedImports = declaration.getNamedImports();
    if (namedImports.length === 0) continue;

    const exported = [...target.getExportedDeclarations().keys()];
    const pkg = specifier.startsWith(".") ? null : packageDirName(specifier);
    const version = pkg ? installedVersion(pkg) : null;

    for (const namedImport of namedImports) {
      const name = namedImport.getName();
      if (exported.includes(name)) continue;

      const ranked = rankSimilar(name, exported);
      findings.push({
        severity: "high",
        file,
        line: namedImport.getStartLineNumber(),
        claim: `${specifier}.${name}`,
        verdict: "missing-export",
        evidence: [
          `${pkg ?? specifier}${version ? ` ${version}` : ""} resolved to ${relative(root, target.getFilePath())}`,
          `"${name}" is not exported - ${exported.length} exports available`,
          ranked.length
            ? `closest real names: ${ranked.join(", ")}`
            : "no similarly named export exists",
        ],
      });
    }
  }
}

emit({ findings });
