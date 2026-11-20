/**
 * TypeScript half of the fail-open checks. Verified against ts-morph 27.0.2.
 * Mirrors killscore/checks/fail_open.py: same four detectors, same verdict vocabulary,
 * and the same two-signal rule before anything is reported.
 *
 * Emits JSON on stdout: {findings: [{severity, file, line, claim, verdict, source_line}]}
 */

import { existsSync } from "node:fs";
import { join, relative } from "node:path";
import { Node, Project, SyntaxKind } from "ts-morph";

const root = process.argv[2];
const URLISH = /url|uri|endpoint|host|dsn|conn|base|webhook|origin/i;
// Mirrors CREDENTIAL_PARTS in fail_open.py: WEBHOOK_SECRET names a credential, not a URL.
const CREDENTIAL_PARTS = new Set([
  "secret", "key", "token", "password", "passwd", "signing", "signature", "credential", "credentials",
]);

function namesAUrl(name) {
  if (!name || !URLISH.test(name)) return false;
  const snake = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
  return !snake.split(/[^a-z0-9]+/).some((part) => CREDENTIAL_PARTS.has(part));
}

/** Mirrors `_tests_name`: `url !== ""`, `!url`, `url || fallback` test the value outside an `if`. */
function testsName(node, bound) {
  const isBound = (n) => Node.isIdentifier(n) && n.getText() === bound;
  if (Node.isBinaryExpression(node)) {
    const op = node.getOperatorToken().getText();
    if (["===", "!==", "==", "!="].includes(op)) {
      const sides = [node.getLeft(), node.getRight()];
      return sides.some(isBound) && sides.some((side) => isEmptyFallback(side));
    }
    if (op === "||" || op === "&&" || op === "??") return isBound(node.getLeft());
  }
  if (Node.isPrefixUnaryExpression(node) && node.getOperatorToken() === SyntaxKind.ExclamationToken) {
    return isBound(node.getOperand());
  }
  return false;
}
const GATE = /auth|tier|gate|permission|access|allow/i;
// Mirrors QUESTION_WORDS in fail_open.py: a gate's name asks a yes/no question.
const QUESTION_WORDS = new Set([
  "is", "has", "can", "check", "may", "should", "verify", "validate", "authorize",
  "authorise", "allow", "allowed", "permit", "require", "ensure",
]);

function readsAsQuestion(name) {
  const words = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/);
  return QUESTION_WORDS.has(words.find((word) => word) ?? "");
}

function emit(payload) {
  process.stdout.write(JSON.stringify(payload));
  process.exit(0);
}

// Must be loud: silently returning zero findings for a bad path is itself a fail-open.
if (!root || !existsSync(root)) emit({ error: `path not found: ${root}` });

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

function record(node, severity, claim, verdict) {
  findings.push({
    severity,
    file: relative(root, node.getSourceFile().getFilePath()),
    line: node.getStartLineNumber(),
    claim,
    verdict,
    source_line: `${node.getStartLineNumber()}: ${node.getText().split("\n")[0].trim()}`,
  });
}

/** `process.env.X` in any nesting. */
function isProcessEnvAccess(node) {
  if (!Node.isPropertyAccessExpression(node) && !Node.isElementAccessExpression(node)) return false;
  return node.getExpression().getText().replace(/\s/g, "") === "process.env";
}

function isEmptyFallback(node) {
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) {
    return node.getLiteralValue() === "";
  }
  const text = node.getText();
  return text === "null" || text === "undefined";
}

/** Nearest enclosing name: `const apiUrl = ...` or `{ baseUrl: ... }`. */
function enclosingName(node) {
  let current = node.getParent();
  while (current) {
    if (Node.isVariableDeclaration(current)) return current.getName();
    if (Node.isPropertyAssignment(current)) return current.getName();
    if (Node.isBinaryExpression(current) && current.getOperatorToken().getText() === "=") {
      return current.getLeft().getText();
    }
    current = current.getParent();
  }
  return null;
}

function insideUrlTemplate(node) {
  let current = node.getParent();
  while (current) {
    if (Node.isTemplateExpression(current) && current.getText().includes("://")) return true;
    current = current.getParent();
  }
  return false;
}

/** The condition a node owns, for every construct that tests one. */
function conditionOf(node) {
  if (Node.isIfStatement(node) || Node.isWhileStatement(node)) return node.getExpression();
  if (Node.isConditionalExpression(node)) return node.getCondition();
  return null;
}

/**
 * Mirrors `_is_guarded` in fail_open.py: the empty value is tested before anything uses it.
 * Either the expression is itself a condition, or the name it is bound to is tested later
 * in the same function (or file). An unrelated `if` guards nothing.
 */
function isGuarded(node, bound) {
  let current = node;
  let parent = current.getParent();
  while (parent && !Node.isStatement(parent)) {
    if (Node.isConditionalExpression(parent) && parent.getCondition() === current) return true;
    current = parent;
    parent = current.getParent();
  }
  if (parent && conditionOf(parent) === current) return true;

  if (!bound || bound.includes(".")) return false;
  const scope =
    node.getFirstAncestor((a) => Node.isFunctionLikeDeclaration(a) || Node.isArrowFunction(a)) ??
    node.getSourceFile();
  const assignedAt = node.getEndLineNumber();
  let guarded = false;
  scope.forEachDescendant((candidate, traversal) => {
    if (candidate.getStartLineNumber() < assignedAt) return;
    const condition = conditionOf(candidate);
    const mentions = condition
      ? [condition, ...condition.getDescendants()].some((n) => Node.isIdentifier(n) && n.getText() === bound)
      : candidate.getStartLineNumber() > node.getStartLineNumber() && testsName(candidate, bound);
    if (mentions) {
      guarded = true;
      traversal.stop();
    }
  });
  return guarded;
}

function lastStatementOf(fn) {
  const body = fn.getBody?.();
  if (!body || !Node.isBlock(body)) return null;
  const statements = body.getStatements();
  return statements.length ? statements[statements.length - 1] : null;
}

function hasIfStatement(fn) {
  const body = fn.getBody?.();
  if (!body || !Node.isBlock(body)) return false;
  return body.getStatements().some((s) => Node.isIfStatement(s));
}

function functionName(fn) {
  if (typeof fn.getName === "function" && fn.getName()) return fn.getName();
  const declared = enclosingName(fn);
  return declared ?? "";
}

for (const sourceFile of project.getSourceFiles()) {
  if (sourceFile.getFilePath().includes("/node_modules/")) continue;

  sourceFile.forEachDescendant((node) => {
    // 1. process.env.X || "" flowing into a URL - HIGH
    if (Node.isBinaryExpression(node)) {
      const operator = node.getOperatorToken().getText();
      if ((operator === "||" || operator === "??") && isProcessEnvAccess(node.getLeft())) {
        if (isEmptyFallback(node.getRight())) {
          const variable = node.getLeft().getText();
          const bound = enclosingName(node);
          const signal =
            namesAUrl(variable) || namesAUrl(bound) || insideUrlTemplate(node);
          if (signal && !isGuarded(node, bound)) {
            record(node, "high", `${variable} ${operator} ${node.getRight().getText()}`, "env-default-degrades-url");
          }
        }
      }
    }

    // 2. Gate that falls through to permissive - HIGH
    if (
      Node.isFunctionDeclaration(node) ||
      Node.isMethodDeclaration(node) ||
      Node.isArrowFunction(node) ||
      Node.isFunctionExpression(node)
    ) {
      const name = functionName(node);
      if (name && GATE.test(name) && readsAsQuestion(name) && hasIfStatement(node)) {
        const last = lastStatementOf(node);
        if (last) {
          const text = last.getText().replace(/;$/, "").trim();
          if (text === "return true" || text === "next()" || text === "return next()") {
            record(last, "high", `${name}() falls through to ${text}`, "gate-fails-open");
          }
        }
      }
    }

    // 3. Empty catch block - MEDIUM
    if (Node.isCatchClause(node) && node.getBlock().getStatements().length === 0) {
      record(node, "medium", "empty catch block discards the error", "swallowed-exception");
    }

    // 4. Wildcard CORS with credentials - MEDIUM
    if (Node.isObjectLiteralExpression(node)) {
      let wildcard = false;
      let credentials = false;
      for (const property of node.getProperties()) {
        if (!Node.isPropertyAssignment(property)) continue;
        const key = property.getName().replace(/["']/g, "");
        const value = property.getInitializer();
        if (!value) continue;
        if (/^(origin|origins|allowedOrigins|allow_origins)$/i.test(key)) {
          const text = value.getText().replace(/\s/g, "");
          wildcard = text === '"*"' || text === "'*'" || /\[["']\*["']\]/.test(text);
        }
        if (/^(credentials|allow_credentials|withCredentials)$/i.test(key)) {
          credentials = value.getText() === "true";
        }
      }
      if (wildcard && credentials) {
        record(node, "medium", 'origin "*" with credentials: true', "cors-wildcard-with-credentials");
      }
    }
  });
}

emit({ findings });
