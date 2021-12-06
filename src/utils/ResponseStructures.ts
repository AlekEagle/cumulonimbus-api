export namespace ResponseStructures {
  export class InsufficientPermissions {
    public readonly code: string = 'INSUFFICIENT_PERMISSIONS';
    public readonly message: string = 'Missing Permissions';
    constructor() {}
  }
  export class InvalidPassword {
    public readonly code: string = 'INVALID_PASSWORD';
    public readonly message: string = 'Invalid Password';
    constructor() {}
  }
  export class NotAuthenticated {
    public readonly code: string = 'NO_AUTH';
    public readonly message: string = 'Not Authenticated';
    constructor() {}
  }
  export class MissingFields {
    public readonly code: string = 'MISSING_FIELDS';
    public readonly message: string = 'Missing Fields';
    fields: string[];
    constructor(fields: string[]) {
      this.fields = fields;
    }
  }
  export class GenericError {
    public readonly code: string = 'GENERIC_ERROR';
    private __message: string;
    public get message(): string {
      return this.__message;
    }
    constructor(message: string) {
      this.__message = message;
    }
  }
}
