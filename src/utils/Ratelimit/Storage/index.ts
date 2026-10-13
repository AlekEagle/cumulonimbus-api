export interface RatelimitSubject {
  bucket: string;
  subject: string;
}

export interface RatelimitData {
  expiresAt: Date;
  requests: Record<number, number>;
  max: number;
}

/**
 * Represents an entry in the ratelimit storage, should only be created by the storage itself.
 */
export class RatelimitEntry {
  constructor(
    private _subject: RatelimitSubject,
    private _data: RatelimitData,
    private _parent: BaseRatelimitStorage,
  ) {}

  get subject() {
    return this._subject;
  }

  get data() {
    return this._data;
  }

  /**
   * Push a request onto the ratelimit entry with its timestamp and score.
   */
  public async pushRequest(
    requestTime: number,
    score: number = 1,
  ): Promise<this> {
    this._data.requests[requestTime] = score;
    await this._parent.set(this._subject, this._data);
    return this;
  }
}

/**
 * Base class for the ratelimit storage system. Extendable for custom storage implementations.
 */
export default class BaseRatelimitStorage {
  // == Static Properties ==
  // None for now.

  // == Static Methods ==
  // None for now.

  // == Instance Properties ==
  protected pruneIntervalID: ReturnType<typeof setInterval> | null = null;

  // == Constructor ==
  constructor(pruneInterval: number = 0) {
    if (pruneInterval > 0)
      this.pruneIntervalID = setInterval(() => {
        this.prune();
      }, pruneInterval);
  }

  // == Automatic Pruning Control ==
  public startAutoPrune(interval: number): void {
    if (this.pruneIntervalID !== null) this.stopAutoPrune();
    this.pruneIntervalID = setInterval(() => {
      this.prune();
    }, interval);
  }

  public stopAutoPrune(): void {
    if (this.pruneIntervalID !== null) {
      clearInterval(this.pruneIntervalID);
      this.pruneIntervalID = null;
    }
  }

  public get isAutoPruning(): boolean {
    return this.pruneIntervalID !== null;
  }

  // == Instance Methods ==
  // Methods that should be implemented in subclasses.
  protected prune(): Promise<number> {
    throw new Error("Method 'prune' must be implemented in the subclass.");
  }

  public get(subject: RatelimitSubject): Promise<RatelimitEntry | null> {
    throw new Error("Method 'get' must be implemented in the subclass.");
  }

  public has(subject: RatelimitSubject): Promise<boolean> {
    throw new Error("Method 'has' must be implemented in the subclass.");
  }

  public set(
    subject: RatelimitSubject,
    data: RatelimitData,
  ): Promise<RatelimitEntry> {
    throw new Error("Method 'set' must be implemented in the subclass.");
  }

  public delete(subject: RatelimitSubject): Promise<RatelimitEntry | null> {
    throw new Error("Method 'delete' must be implemented in the subclass.");
  }
}
