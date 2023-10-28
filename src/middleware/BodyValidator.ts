import { Request, Response, NextFunction } from 'express';

export declare type ValidBodyTypes =
  | 'any'
  | 'array'
  | 'number'
  | 'boolean'
  | 'string'
  | 'null';

export class ExtendedBodyValidatorOptions {
  constructor(
    public type: ValidBodyTypes,
    public optional: boolean = false,
    public arrayType: ValidBodyTypes = 'any',
  ) {}
}

export interface BodyValidatorOptions {
  [key: string]:
    | ValidBodyTypes
    | BodyValidatorOptions
    | ExtendedBodyValidatorOptions;
}

export default function BodyValidator(options: BodyValidatorOptions) {}
