#!/usr/bin/env node
// CI check for PRD §9.4 / US-095: heir-facing walkthrough copy must stay at or
// below a US 8th-grade reading level. Dependency-free on purpose, so it runs in
// the same guardrail phase as the frontend security checks.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const i18nPath = join(root, "src", "i18n", "en.json");
const targetGrade = 8.0;
const requiredScamPhrase = "we will never contact you";

function collectStrings(value, out = []) {
  if (typeof value === "string") {
    out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
    return out;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) collectStrings(item, out);
  }
  return out;
}

function cleanText(text) {
  return text
    .replace(/\{\{[^}]+\}\}/g, " ")
    .replace(/[/-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function words(text) {
  return cleanText(text).match(/[A-Za-z]+(?:'[A-Za-z]+)?/g) ?? [];
}

function sentenceCount(text) {
  const sentences = cleanText(text)
    .split(/[.!?]+/)
    .map((sentence) => sentence.trim())
    .filter(Boolean);
  return Math.max(1, sentences.length);
}

function syllables(rawWord) {
  const word = rawWord.toLowerCase().replace(/[^a-z]/g, "");
  if (word.length <= 3) return 1;
  const normalized = word.replace(/(?:e|es|ed)$/, "");
  const groups = normalized.match(/[aeiouy]+/g);
  return Math.max(1, groups?.length ?? 1);
}

function fleschKincaidGrade(text) {
  const wordList = words(text);
  const wordTotal = Math.max(1, wordList.length);
  const sentenceTotal = sentenceCount(text);
  const syllableTotal = wordList.reduce((sum, word) => sum + syllables(word), 0);
  return 0.39 * (wordTotal / sentenceTotal) + 11.8 * (syllableTotal / wordTotal) - 15.59;
}

const en = JSON.parse(readFileSync(i18nPath, "utf8"));
const copyStrings = collectStrings(en.pages?.heirWalkthrough);
const copy = copyStrings.join(" ");
const grade = fleschKincaidGrade(copy);
const scamMentions = copy.toLowerCase().split(requiredScamPhrase).length - 1;

if (scamMentions < 2) {
  console.error(
    `Heir walkthrough must repeat "${requiredScamPhrase}" at least twice; found ${scamMentions}.`,
  );
  process.exit(1);
}

if (grade > targetGrade) {
  console.error(
    `Heir walkthrough copy is grade ${grade.toFixed(2)}, above target ${targetGrade.toFixed(1)}.`,
  );
  process.exit(1);
}

console.log(`Heir walkthrough copy grade ${grade.toFixed(2)} <= ${targetGrade.toFixed(1)}.`);
