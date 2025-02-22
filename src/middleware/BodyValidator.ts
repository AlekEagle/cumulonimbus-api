import type { Request, Response, NextFunction } from 'express';
import { Errors } from '../utils/TemplateResponses.js';

export type ValidBodyTypes = 'any' | 'array' | 'number' | 'boolean' | 'string';

export class ExtendedValidBodyTypes {
  private _type: ValidBodyTypes;
  private _optional: boolean;
  private _arrayType: ValidBodyTypes;

  public get type(): typeof this._type {
    return this._type;
  }

  public get optional(): typeof this._optional {
    return this._optional;
  }

  public get arrayType(): typeof this._arrayType {
    return this._arrayType;
  }

  constructor() {}

  public any(): this {
    this._type = 'any';
    return this;
  }

  public string(): this {
    this._type = 'string';
    return this;
  }

  public number(): this {
    this._type = 'number';
    return this;
  }

  public boolean(): this {
    this._type = 'boolean';
    return this;
  }

  public array(type: ValidBodyTypes = 'any'): this {
    this._type = 'array';
    this._arrayType = type;
    return this;
  }

  public notRequired(): this {
    this._optional = true;
    return this;
  }
}

export type ValidBodyOptions =
  | ValidBodyTypes
  | ExtendedValidBodyTypes
  | ValidBodyTemplate;

export interface ValidBodyTemplate {
  [key: string]: ValidBodyOptions | ValidBodyTemplate;
}

function fieldTester(
  templateType: ValidBodyOptions | null,
  field: any,
): boolean {
  if (templateType instanceof ExtendedValidBodyTypes) {
    if (typeof templateType.type === 'undefined')
      throw new Error('Type not set.');
    if (templateType.optional && field === undefined) return true;
    if (templateType.type === 'array') {
      if (!Array.isArray(field)) return false;
      if (templateType.arrayType === 'any') return true;
      return field.every((item) => fieldTester(templateType.arrayType, item));
    }
    return typeof field === templateType.type;
  }
  if (templateType === 'any') return true;
  return typeof field === templateType;
}

export default function BodyValidator(template: ValidBodyTemplate) {
  return (req: Request, res: Response, next: NextFunction) => {
    let invalidFields: string[] = [];

    for (const [key, value] of Object.entries(template)) {
      if (!fieldTester(value, req.body[key])) invalidFields.push(key);
    }

    if (invalidFields.length > 0) {
      return res.status(400).json(new Errors.MissingFields(invalidFields));
    } else next();
  };
}
