export interface IgnoreMatcher {
  ignores(relPath: string, isDir: boolean): boolean;
}

interface IgnoreRule {
  re: RegExp;
  negate: boolean;
  dirOnly: boolean;
}

function globToRegex(glob: string): string {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] as string;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        const atSegmentStart = i === 0 || glob[i - 1] === '/';
        if (atSegmentStart && glob[i + 2] === '/') {
          out += '(?:.*/)?';
          i += 2;
          continue;
        }
        out += '.*';
        i += 1;
        continue;
      }
      out += '[^/]*';
    } else if (c === '?') {
      out += '[^/]';
    } else if (c === '[') {
      const end = glob.indexOf(']', i + 1);
      if (end === -1) {
        out += '\\[';
        continue;
      }
      let cls = glob.slice(i + 1, end);
      if (cls.startsWith('!')) cls = '^' + cls.slice(1);
      out += `[${cls.replace(/\\/g, '\\\\')}]`;
      i = end;
    } else if ('\\^$.|+(){}'.includes(c)) {
      out += '\\' + c;
    } else {
      out += c;
    }
  }
  return out;
}

/** A small .gitignore matcher: comments, negation, anchoring, dir-only patterns, *, ** and ?. */
export function parseGitignore(text: string): IgnoreMatcher {
  const rules: IgnoreRule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    let negate = false;
    if (line.startsWith('!')) {
      negate = true;
      line = line.slice(1);
    }
    let dirOnly = false;
    if (line.endsWith('/')) {
      dirOnly = true;
      line = line.slice(0, -1);
    }
    if (!line) continue;
    const anchored = line.includes('/');
    if (line.startsWith('/')) line = line.slice(1);
    const body = globToRegex(line);
    rules.push({ re: new RegExp(anchored ? `^${body}$` : `(?:^|/)${body}$`), negate, dirOnly });
  }
  return {
    ignores(relPath: string, isDir: boolean): boolean {
      let ignored = false;
      for (const rule of rules) {
        if (rule.dirOnly && !isDir) continue;
        if (rule.re.test(relPath)) ignored = !rule.negate;
      }
      return ignored;
    },
  };
}
