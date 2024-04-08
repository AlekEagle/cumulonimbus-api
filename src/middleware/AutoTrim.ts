import { RequestHandler } from 'express';

type RecursiveFilter = Array<string | string[] | RecursiveFilter>;

class RecursiveTypeError extends Error {
  public name: string = 'RecursiveTypeError';
  public typeReceived: 'string' | 'array';
  public rawPath: string[];
  public get path(): string {
    return this.rawPath.join('.');
  }
  public get message(): string {
    return `Expected type object for '${this.path}' in filteredKeys, instead got ${this.typeReceived}.`;
  }

  constructor(rawPath: string[], typeReceived: 'string' | 'array') {
    super();
    Object.setPrototypeOf(this, RecursiveTypeError.prototype);
    this.rawPath = rawPath;
    this.typeReceived = typeReceived;
  }
}

// A middleware that will recursively trim values of whitespace, while avoiding specified keys.
export default function AutoTrim(
  omittedKeysFilter: RecursiveFilter = [],
  invertFilter: boolean = false,
): RequestHandler {
  return (req, res, next) => {
    try {
      recursivelyTrim(req.body, omittedKeysFilter, invertFilter);
      next();
    } catch (e) {
      next(e);
    }
  };
}

function recursivelyTrim(
  obj: any,
  filteredKeys: RecursiveFilter = [],
  invertFilter: boolean = false,
) {
  // Turn all strings in filteredKeys into arrays
  const nestedKeys = filteredKeys.map((key) => {
    if (typeof key === 'string') return key.split('.');
    else return key;
  });

  for (let key in obj) {
    // Determine the type of the value
    if (typeof obj[key] === 'string') {
      // Check if this key is actually supposed to be an object (if it has keys after the 0th index)
      if (nestedKeys.some((nestedKey) => nestedKey[0] === key && nestedKey[1]))
        // If it is, throw an error, I expected an object from filteredKeys value but got a string
        throw new RecursiveTypeError([key], 'string');
      // Check if this key is in the filteredKeys array (or not, if invertFilter is true)
      if (
        (invertFilter &&
          nestedKeys.some((nestedKey) => nestedKey[0] === key)) ||
        (!invertFilter && !nestedKeys.some((nestedKey) => nestedKey[0] === key))
      )
        obj[key] = obj[key].trim();
    } else if (Array.isArray(obj[key])) {
      // Check if this key is actually supposed to be an object (if it has keys after the 0th index)
      if (nestedKeys.some((nestedKey) => nestedKey[0] === key && nestedKey[1]))
        // If it is, throw an error, I expected an object from filteredKeys value but got an array
        throw new RecursiveTypeError([key], 'array');
      // Check if this key is in the filteredKeys array (or not, if invertFilter is true)
      if (
        (invertFilter &&
          nestedKeys.some((nestedKey) => nestedKey[0] === key)) ||
        (!invertFilter && !nestedKeys.some((nestedKey) => nestedKey[0] === key))
      )
        // Recurse the array and trim all strings
        obj[key] = obj[key].map((value: any) => {
          if (typeof value === 'string') return value.trim();
          else return value;
        });
    } else if (typeof obj[key] === 'object') {
      // Check if this key has a nested key in filteredKeys (if it has keys after the 0th index)
      if (
        !nestedKeys.some((nestedKey) => nestedKey[0] === key && nestedKey[1])
      ) {
        // if it doesn't, check if this key is in the filteredKeys array (or not, if invertFilter is true)
        if (
          (!invertFilter &&
            nestedKeys.some((nestedKey) => nestedKey[0] === key)) ||
          (invertFilter &&
            !nestedKeys.some((nestedKey) => nestedKey[0] === key))
        )
          // Ignore it and move on
          continue;
      } else {
        // If it does, create a new nested keys array shifted to the left by one (to remove the first key)
        const newNestedKeys = nestedKeys
          .find((nestedKey) => nestedKey[0] === key)!
          .slice(1);

        // Surround this recursion in a try/catch block to catch unexpected type errors
        try {
          recursivelyTrim(obj[key], newNestedKeys, invertFilter);
        } catch (err) {
          throw new RecursiveTypeError([key, ...err.rawPath], err.typeReceived);
        }
      }
    }
  }
}
