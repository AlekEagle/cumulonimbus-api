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

export interface RatelimitSubject {
  ip: string;
  route: string | null;
  uid: string | null;
}

export interface RatelimitData {
  expiresAt: Date;
  requests: Record<number, number>;
  max: number;
}

export class RatelimitStorageObject {
  public get subject(): RatelimitSubject {
    return this._subject;
  }

  public get data(): RatelimitData {
    return this._data;
  }

  public set data(data: RatelimitData) {
    this._data = data;
  }

  constructor(
    private _subject: RatelimitSubject,
    private _data: RatelimitData,
    private _storage: RatelimitStorage,
  ) {}

  public async pushRequest(
    requestTime: number,
    score: number = 1,
  ): Promise<this> {
    this._data = {
      ...this._data,
      requests: { ...this._data.requests, [requestTime]: score },
    };
    this.commit();
    return this;
  }

  public async update(data: Partial<RatelimitData>): Promise<this> {
    this._data = { ...this._data, ...data };
    this.commit();
    return this;
  }

  public async commit(): Promise<this> {
    this._storage.set(this._subject, this._data);
    return this;
  }

  public async destroy(): Promise<boolean> {
    return this._storage.destroy(this._subject);
  }
}

export default class RatelimitStorage {
  // == Static Properties ==

  // == Static Methods ==
  // None for now.

  // == Instance Properties ==
  private data: [RatelimitSubject, RatelimitData][] = [];
  private pruneIntervalID: ReturnType<typeof setInterval> | null = null;

  // == Constructor ==
  constructor(pruneInterval: number = 60e3) {
    if (pruneInterval > 0) {
      this.pruneIntervalID = setInterval(
        this.pruneExpired.bind(this),
        pruneInterval,
      );
    }
  }

  // == Instance Methods ==
  private async pruneExpired(): Promise<number> {
    const toRemove = this.data.filter(
      ([_, data]) =>
        data.expiresAt.getTime() <= Date.now() ||
        Object.entries(data.requests).length < 1,
    );
    await Promise.all(toRemove.map(([sub]) => this.destroy(sub)));
    return toRemove.length;
  }

  public stopAutoPrune(): boolean {
    if (this.pruneIntervalID === null) return false;
    clearInterval(this.pruneIntervalID);
    this.pruneIntervalID = null;
    return true;
  }

  public startAutoPrune(interval: number = 60e3): boolean {
    if (this.pruneIntervalID !== null) return false;
    this.pruneIntervalID = setInterval(this.pruneExpired.bind(this), interval);
    return true;
  }

  public get isAutoPruning(): boolean {
    return this.pruneIntervalID !== null;
  }

  public create(
    subject: RatelimitSubject,
    data: RatelimitData,
  ): RatelimitStorageObject {
    if (this.data.some(([sub]) => deepCompare(sub, subject))) {
      throw new Error('Ratelimit already exists for this subject.');
    }
    this.data.push([subject, data]);
    return new RatelimitStorageObject(subject, data, this);
  }

  public get(subject: RatelimitSubject): RatelimitStorageObject | null {
    // Prune expired data before checking.
    this.pruneExpired();
    const entry = this.data.find(([sub]) => deepCompare(sub, subject));
    if (!entry) return null;
    return new RatelimitStorageObject(entry[0], entry[1], this);
  }

  public has(subject: RatelimitSubject): boolean {
    // Prune expired data before checking
    this.pruneExpired();
    return this.data.some(([sub]) => deepCompare(sub, subject));
  }

  public set(
    subject: RatelimitSubject,
    data: RatelimitData,
  ): RatelimitStorageObject {
    const entry = this.data.find(([sub]) => deepCompare(sub, subject));
    if (!entry) return this.create(subject, data);
    entry[1] = data;
    return new RatelimitStorageObject(subject, data, this);
  }

  public async destroy(subject: RatelimitSubject): Promise<boolean> {
    const index = this.data.findIndex(([sub]) => deepCompare(sub, subject));
    if (index === -1) return false;
    this.data.splice(index, 1);
    return true;
  }
}
