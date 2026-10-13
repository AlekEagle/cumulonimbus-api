import BaseRatelimitStorage, {
  RatelimitSubject,
  RatelimitData,
  RatelimitEntry,
} from './index.js';

function deepCompare(a: any, b: any): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;

  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepCompare(a[i], b[i])) return false;
    }
    return true;
  }

  const keysA = Object.keys(a);
  const keysB = Object.keys(b);
  if (keysA.length !== keysB.length) return false;

  for (const key of keysA) {
    if (!deepCompare(a[key], b[key])) return false;
  }

  return true;
}

export default class MemoryRatelimitStorage extends BaseRatelimitStorage {
  private storage: [RatelimitSubject, RatelimitData][] = [];

  constructor(pruneInterval?: number) {
    super(pruneInterval ?? 0);
  }

  public async prune() {
    const toRemove = this.storage.filter(
      ([_, data]) => data.expiresAt <= new Date(),
    );
    this.storage = this.storage.filter(
      ([_, data]) => data.expiresAt > new Date(),
    );
    return toRemove.length;
  }

  public async get(subject: RatelimitSubject) {
    await this.prune();
    const entry = this.storage.find(([subj, _]) => deepCompare(subj, subject));
    if (!entry) return null;
    const [subj, data] = entry;
    return new RatelimitEntry(subj, data, this);
  }

  public async has(subject: RatelimitSubject) {
    // Prune immediately to prevent returning stale entries
    await this.prune();
    return this.storage.some(([subj, _]) => deepCompare(subj, subject));
  }

  public async set(subject: RatelimitSubject, data: RatelimitData) {
    const index = this.storage.findIndex(([subj, _]) =>
      deepCompare(subj, subject),
    );
    if (index === -1) {
      this.storage.push([subject, data]);
    } else {
      this.storage[index][1] = data;
    }
    return new RatelimitEntry(subject, data, this);
  }

  public async delete(subject: RatelimitSubject) {
    const index = this.storage.findIndex(([subj, _]) =>
      deepCompare(subj, subject),
    );
    if (index !== -1) {
      const [subj, data] = this.storage.splice(index, 1)[0];
      return new RatelimitEntry(subj, data, this);
    }
    return null;
  }
}
