import type { Request, Response, NextFunction } from 'express';
import { Errors } from '../utils/TemplateResponses.js';

export type ValidBodyTypes =
  | 'any'
  | 'array'
  | 'number'
  | 'boolean'
  | 'string'
  | 'record';

export class ExtendedValidBodyTypes {
  private _type: ValidBodyTypes = 'any';
  private _optional: boolean = false;
  private _arrayType: ValidBodyTypes = 'any';
  private _objectTemplate: ValidBodyTemplate | null = null;

  public get type(): typeof this._type {
    return this._type;
  }

  public get optional(): typeof this._optional {
    return this._optional;
  }

  public get arrayType(): typeof this._arrayType {
    return this._arrayType;
  }

  public get objectTemplate(): typeof this._objectTemplate {
    return this._objectTemplate;
  }

  public object(template?: ValidBodyTemplate): this {
    this._type = 'record';
    this._objectTemplate = template ?? null;
    return this;
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

  public array(
    type: ValidBodyTypes = 'any',
    objectTemplate?: ValidBodyTemplate,
  ): this {
    this._type = 'array';
    this._arrayType = type;
    if (type !== 'record' && objectTemplate) {
      throw new Error(
        'Array type must be "record" to provide an object template.',
      );
    } else this._objectTemplate = objectTemplate ?? null;
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
  [key: string]: ValidBodyOptions;
}

function isTemplate(value: any): value is ValidBodyTemplate {
  return (
    value !== null &&
    !(value instanceof ExtendedValidBodyTypes) &&
    typeof value === 'object' &&
    !Array.isArray(value)
  );
}

function fieldTester(
  templateType: ValidBodyOptions | null,
  field: any,
): boolean {
  // Test extended fields
  if (templateType instanceof ExtendedValidBodyTypes) {
    if (field === undefined || field === null) {
      // If the field is undefined or null, check if it is optional
      if (templateType.optional) return true;
      else return false;
    }
    // Handle array types
    if (templateType.type === 'array') {
      if (!Array.isArray(field)) return false;
      if (templateType.arrayType === 'any') return true;
      if (templateType.arrayType === 'record') {
        if (!templateType.objectTemplate) {
          if (field.every((item) => fieldTester('record', item))) return true;
        } else
          throw new Error(
            'fieldTester encountered a record type in an array with an object template. This should not happen.',
          );
      }
      return field.every((item) => fieldTester(templateType.arrayType, item));
    }
    if (templateType.type === 'record') {
      throw new Error(
        'fieldTester was fed a record type on an extended template, this should not happen.',
      );
    }
    return typeof field === templateType.type;
  }
  if (templateType === 'any') return true;
  if (templateType === 'array') return Array.isArray(field);
  if (templateType === 'record')
    return (
      Array.isArray(field) === false &&
      typeof field === 'object' &&
      field !== null
    );
  return typeof field === templateType;
}

function validate(template: ValidBodyTemplate, body: any): string[] {
  let invalidFields: string[] = [];

  for (const [key, valueTemplate] of Object.entries(template)) {
    // If body is undefined or null, all fields are considered invalid
    if (body === undefined || body === null) {
      invalidFields.push(key);
      continue;
    }
    const field = body[key];
    // Test some conditions of ExtendedValidBodyTypes here, fieldTester
    if (valueTemplate instanceof ExtendedValidBodyTypes) {
      if (field === undefined || field === null) {
        // Skip optional fields if they are undefined or null
        if (!valueTemplate.optional) invalidFields.push(key);
        continue;
      }
      // Handle arrays with records that have an object template
      if (
        valueTemplate.type === 'array' &&
        valueTemplate.arrayType === 'record' &&
        valueTemplate.objectTemplate
      ) {
        // If the field is not an array, it is invalid
        if (!Array.isArray(field)) {
          invalidFields.push(key);
          continue;
        }
        for (const [index, item] of field.entries()) {
          // If the item in the field is an array, not an object, or null, it is invalid
          if (
            Array.isArray(item) ||
            typeof item !== 'object' ||
            item === null
          ) {
            invalidFields.push(`${key}[${index}]`);
            continue;
          }
          // Validate the item against the object template
          invalidFields.push(
            ...validate(valueTemplate.objectTemplate, item).map(
              (subKey) => `${key}[${index}].${subKey}`,
            ),
          );
        }
        continue;
      }
      // Handle record types with an object template
      if (valueTemplate.type === 'record') {
        if (Array.isArray(field)) {
          invalidFields.push(key);
          continue;
        }
        if (typeof field !== 'object' || field === null) {
          invalidFields.push(key);
          continue;
        }
        if (!valueTemplate.objectTemplate) continue;
        // Validate each sub-field against the object template
        invalidFields.push(
          ...validate(valueTemplate.objectTemplate, field).map(
            (subKey) => `${key}.${subKey}`,
          ),
        );
        continue;
      }
    }
    // If the template expects an object but the field is not an object, mark it as invalid
    if (isTemplate(valueTemplate) && (!field || typeof field !== 'object')) {
      invalidFields.push(key);
      continue;
    }
    // Handle nested object templates
    if (isTemplate(valueTemplate)) {
      invalidFields.push(
        ...validate(valueTemplate, field).map((subKey) => `${key}.${subKey}`),
      );
      continue;
    }
    // Handle primitive types and other non-object templates
    if (!fieldTester(valueTemplate, field)) invalidFields.push(key);
  }

  return invalidFields;
}

export default function BodyValidator(template: ValidBodyTemplate) {
  return (req: Request, res: Response, next: NextFunction) => {
    const invalidFields = validate(template, req.body);

    if (invalidFields.length > 0) {
      return res.status(400).json(new Errors.MissingFields(invalidFields));
    } else next();
  };
}
