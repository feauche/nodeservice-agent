#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const argument = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
};

const tag = argument('--tag');
const ref = argument('--ref') ?? 'HEAD';
if (!tag || !/^v\d+\.\d+\.\d+$/.test(tag)) throw new Error('Укажите релизный тег: --tag vX.Y.Z');

const parseVersion = (value) => {
  const match = value.replace(/^v/, '').match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) throw new Error(`Некорректная версия: ${value}`);
  return match.slice(1).map(Number);
};
const compareVersions = (left, right) => {
  const a = parseVersion(left);
  const b = parseVersion(right);
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return 0;
};
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();

const version = tag.slice(1);
const previous = git('tag', '--merged', ref)
  .split('\n')
  .filter((item) => /^v\d+\.\d+\.\d+$/.test(item) && compareVersions(item, tag) < 0)
  .sort((left, right) => compareVersions(right, left))[0];
if (!previous) throw new Error('Не найден предыдущий релизный тег vX.Y.Z.');

const changelog = JSON.parse(readFileSync(new URL('../CHANGELOG.json', import.meta.url), 'utf8'));
if (!changelog.some((entry) => entry.version === version)) {
  throw new Error(`Нет записи CHANGELOG для выпускаемой версии ${version}.`);
}
const releases = changelog
  .filter((entry) => compareVersions(entry.version, previous) > 0 && compareVersions(entry.version, version) <= 0)
  .sort((left, right) => compareVersions(right.version, left.version));
if (releases.length === 0) throw new Error(`После ${previous} нет записей CHANGELOG для ${tag}.`);

const output = [`# ${tag}`, '', `## Что изменилось после ${previous}`, ''];
for (const release of releases) {
  output.push(`### ${release.version}`, '', ...release.items.map((item) => `- ${item}`), '');
}
output.pop();
process.stdout.write(`${output.join('\n')}\n`);
