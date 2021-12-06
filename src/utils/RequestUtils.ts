import UAParser from 'ua-parser-js';
import { Cumulonimbus } from '../types';

export namespace ResponseConstructors {
  export namespace Errors {
    export class Permissions implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'INSUFFICIENT_PERMISSIONS_ERROR';
      public readonly message: string = 'Missing Permissions';
      constructor() {}
    }

    export class InvalidUser implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'INVALID_USER_ERROR';
      public readonly message: string = 'Invalid User';
      constructor() {}
    }

    export class UserExists implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'USER_EXISTS_ERROR';
      public readonly message: string = 'User Already Exists';
      constructor() {}
    }

    export class InvalidPassword implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'INVALID_PASSWORD_ERROR';
      public readonly message: string = 'Invalid Password';
      constructor() {}
    }

    export class InvalidSession implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'INVALID_SESSION_ERROR';
      public readonly message: string = 'Invalid Session';
      constructor() {}
    }

    export class InvalidDomain implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'INVALID_DOMAIN_ERROR';
      public readonly message: string = 'Invalid Domain';
      constructor() {}
    }

    export class InvalidSubdomain implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'INVALID_SUBDOMAIN_ERROR';
      public readonly message: string =
        'Subdomain cannot be longer than 63 characters';
      private __parsedSubdomain: string;
      public get parsedSubdomain() {
        return this.__parsedSubdomain;
      }
      constructor(parsedSubdomain: string) {
        this.__parsedSubdomain = parsedSubdomain;
      }
    }

    export class SubdomainNotSupported
      implements Cumulonimbus.Structures.Error
    {
      public readonly code: string = 'SUBDOMAIN_NOT_SUPPORTED_ERROR';
      public readonly message: string =
        'Domain Does Not Support Using A Subdomain';
      constructor() {}
    }

    export class MissingFields implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'MISSING_FIELDS_ERROR';
      public readonly message: string = 'Missing Fields';
      fields: string[];
      constructor(fields: string[]) {
        this.fields = fields;
      }
    }

    export class FileMissing implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'FILE_NOT_FOUND_ERROR';
      public readonly message: string = 'File Not Found';
      constructor() {}
    }

    export class SessionMissing implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'SESSION_NOT_FOUND_ERROR';
      public readonly message: string = 'Session Not Found';
      constructor() {}
    }

    export class Internal implements Cumulonimbus.Structures.Error {
      public readonly code: string = 'INTERNAL_SERVER_ERROR';
      public readonly message: string = 'Internal Server Error';
      constructor() {}
    }

    export class Generic implements Cumulonimbus.Structures.Error {
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

  export namespace Success {
    export class Generic implements Cumulonimbus.Structures.Success {
      public readonly success: boolean = true;
      public message?: string = undefined;
      constructor(message?: string) {
        if (message !== undefined) {
          this.message = message;
        }
      }
    }
  }
}

export function browserName(ua: UAParser.IResult) {
  if (
    ua.browser.name === undefined ||
    ua.browser.version === undefined ||
    ua.os.name === undefined ||
    (ua.os.version === undefined && ua.cpu.architecture === undefined)
  )
    return ua.ua;
  else
    return `${ua.browser.name} v${ua.browser.version} on ${ua.os.name} ${ua.os.version} ${ua.cpu.architecture}`;
}

export declare type ValidFieldTypes =
  | 'string'
  | 'number'
  | 'array'
  | 'boolean'
  | 'null'
  | 'any';
export class FieldTypeOptions {
  public type: ValidFieldTypes;
  public arrayType?: ValidFieldTypes = null;
  public optional: boolean = false;
  constructor(
    type: ValidFieldTypes,
    optional: boolean = false,
    arrayType: ValidFieldTypes = 'any'
  ) {
    this.type = type;
    this.optional = optional;
    if (this.type === 'array') this.arrayType = arrayType;
  }
}
export declare type InvalidFieldsStruct = {
  [key: string]: ValidFieldTypes | FieldTypeOptions | InvalidFieldsStruct;
};

export function getInvalidFields(
  body: {
    [key: string]: string | number | boolean | any[] | null;
  },
  template: InvalidFieldsStruct
) {
  let invalidFields: any = Object.entries(template).filter(e => {
    if (typeof e[1] === 'string') {
      if (body[e[0]] === null) {
        return e[1] !== 'null';
      } else {
        switch (e[1]) {
          case 'any':
            return false;
          case 'array':
            return !Array.isArray(body[e[0]]);
          case 'number':
            return typeof body[e[0]] !== 'number';
          case 'boolean':
            return typeof body[e[0]] !== 'boolean';
          case 'string':
            return typeof body[e[0]] !== 'string';
          case 'null':
            return body[e[0]] !== null;
        }
      }
    } else if (e[1] instanceof FieldTypeOptions) {
      if (e[1].optional) return false;
      if (body[e[0]] === null) {
        return e[1].type !== 'null';
      } else {
        switch (e[1].type) {
          case 'any':
            return false;
          case 'array':
            return Array.isArray(body[e[0]]);
          case 'number':
            return typeof body[e[0]] !== 'number';
          case 'boolean':
            return typeof body[e[0]] !== 'boolean';
          case 'string':
            return typeof body[e[0]] !== 'string';
          case 'null':
            return body[e[0]] !== null;
        }
      }
    } else {
      return getInvalidFields(body[e[0]] as any, e[1]).length > 0;
    }
  });
  return invalidFields.map((a: [string, any]) => a[0]);
}

export function validateSubdomain(sd: string) {
  return sd
    .trim()
    .split('')
    .filter(a => a.match(/[a-z0-9- ]/i))
    .join('')
    .split(/\s/g)
    .filter(a => a !== '')
    .join('-');
}
