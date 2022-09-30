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

// Create a middleware that modifies the request body in place to trim all string values.
// The function can recurse into objects and arrays.
// You can use periods to specify nested keys, e.g. 'user.name' will trim the 'name' key of the 'user' object.
// By default it will trim all values, except for those specified in the filteredKeys array.
// If invertFilter is true, it will trim only the values specified in the filteredKeys array.
export default function AutoTrim(
  filteredKeys: RecursiveFilter = [],
  invertFilter: boolean = false
): RequestHandler {
  return (req, res, next) => {
    try {
      recursivelyTrim(req.body, filteredKeys, invertFilter);
      next();
    } catch (e) {
      next(e);
    }
  };
}

function recursivelyTrim(
  obj: any,
  filteredKeys: RecursiveFilter = [],
  invertFilter: boolean = false
) {
  // Turn all strings in filteredKeys into arrays
  const nestedKeys = filteredKeys.map(key => {
    if (typeof key === 'string') return key.split('.');
    else return key;
  });

  for (let key in obj) {
    // Determine the type of the value
    if (typeof obj[key] === 'string') {
      // Check if this key is actually supposed to be an object (if it has keys after the 0th index)
      if (nestedKeys.some(nestedKey => nestedKey[0] === key && nestedKey[1]))
        // If it is, throw an error, I expected an object from filteredKeys value but got a string
        throw new RecursiveTypeError([key], 'string');
      // Check if this key is in the filteredKeys array (or not, if invertFilter is true)
      if (
        (invertFilter && nestedKeys.some(nestedKey => nestedKey[0] === key)) ||
        (!invertFilter && !nestedKeys.some(nestedKey => nestedKey[0] === key))
      )
        obj[key] = obj[key].trim();
    } else if (Array.isArray(obj[key])) {
      // Check if this key is actually supposed to be an object (if it has keys after the 0th index)
      if (nestedKeys.some(nestedKey => nestedKey[0] === key && nestedKey[1]))
        // If it is, throw an error, I expected an object from filteredKeys value but got an array
        throw new RecursiveTypeError([key], 'array');
      // Check if this key is in the filteredKeys array (or not, if invertFilter is true)
      if (
        (invertFilter && nestedKeys.some(nestedKey => nestedKey[0] === key)) ||
        (!invertFilter && !nestedKeys.some(nestedKey => nestedKey[0] === key))
      )
        // Recurse the array and trim all strings
        obj[key] = obj[key].map((value: any) => {
          if (typeof value === 'string') return value.trim();
          else return value;
        });
    } else if (typeof obj[key] === 'object') {
      // Check if this key has a nested key in filteredKeys (if it has keys after the 0th index)
      if (!nestedKeys.some(nestedKey => nestedKey[0] === key && nestedKey[1])) {
        // if it doesn't, check if this key is in the filteredKeys array (or not, if invertFilter is true)
        if (
          (!invertFilter &&
            nestedKeys.some(nestedKey => nestedKey[0] === key)) ||
          (invertFilter && !nestedKeys.some(nestedKey => nestedKey[0] === key))
        )
          // Ignore it and move on
          continue;
      } else {
        // If it does, create a new nested keys array shifted to the left by one (to remove the first key)
        const newNestedKeys = nestedKeys
          .find(nestedKey => nestedKey[0] === key)!
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
