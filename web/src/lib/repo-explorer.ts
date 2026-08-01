import { promises as fs } from 'fs';
import path from 'path';

const REPO_ROOT = path.join(process.cwd(), 'src', 'demo-repo');

function resolveSafe(relativePath: string): string {
  const resolved = path.resolve(REPO_ROOT, relativePath);
  if (!resolved.startsWith(REPO_ROOT + path.sep) && resolved !== REPO_ROOT) {
    throw new Error('Path escapes the sandboxed demo-repo directory — not allowed.');
  }
  return resolved;
}

export async function listFiles(relativeDir: string): Promise<string[]> {
  const dir = resolveSafe(relativeDir);
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return entries.map((e) => (e.isDirectory() ? `${e.name}/` : e.name));
}

export async function readFile(relativeFilePath: string): Promise<string> {
  const filePath = resolveSafe(relativeFilePath);
  return fs.readFile(filePath, 'utf-8');
}
