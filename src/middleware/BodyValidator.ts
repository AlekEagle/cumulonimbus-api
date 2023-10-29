import type { Request, Response, NextFunction } from 'express';
import { Errors } from '../utils/TemplateResponses.js';

export type ValidBodyTypes = 'any' | 'array' | 'number' | 'boolean' | 'string';

export class ExtendedValidBodyTypes {
  constructor(
    public type: ValidBodyTypes,
    public optional: boolean = false,
    public arrayType: ValidBodyTypes = 'any',
  ) {}
}

export type ValidBodyOptions =
  | ValidBodyTypes
  | ExtendedValidBodyTypes
  | ValidBodyTemplate;

export interface ValidBodyTemplate {
  [key: string]: ValidBodyOptions | ValidBodyTemplate;
}

function fieldTester(templateType: ValidBodyOptions, field: any): boolean {
  if (templateType instanceof ExtendedValidBodyTypes) {
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
