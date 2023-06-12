export declare type ValidFieldTypes =
  | "string"
  | "number"
  | "array"
  | "boolean"
  | "null"
  | "any";
export class FieldTypeOptions {
  public type: ValidFieldTypes;
  public arrayType?: ValidFieldTypes = null;
  public optional: boolean = false;
  constructor(
    type: ValidFieldTypes,
    optional: boolean = false,
    arrayType: ValidFieldTypes = "any"
  ) {
    this.type = type;
    this.optional = optional;
    if (this.type === "array") this.arrayType = arrayType;
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
  let invalidFields: any = Object.entries(template).filter((e) => {
    if (typeof e[1] === "string") {
      if (body[e[0]] === null) {
        return e[1] !== "null";
      } else {
        switch (e[1]) {
          case "any":
            return false;
          case "array":
            return !Array.isArray(body[e[0]]);
          case "number":
            return typeof body[e[0]] !== "number";
          case "boolean":
            return typeof body[e[0]] !== "boolean";
          case "string":
            return typeof body[e[0]] !== "string" || body[e[0]] === "";
          case "null":
            return body[e[0]] !== null;
        }
      }
    } else if (e[1] instanceof FieldTypeOptions) {
      if (e[1].optional) return false;
      if (body[e[0]] === null) {
        return e[1].type !== "null";
      } else {
        switch (e[1].type) {
          case "any":
            return false;
          case "array":
            if (e[1].arrayType)
              return (
                !Array.isArray(body[e[0]]) &&
                (body[e[0]] as any[]).every(
                  (a) => typeof a === (e[1] as FieldTypeOptions).arrayType
                )
              );
            else return !Array.isArray(body[e[0]]);
          case "number":
            return typeof body[e[0]] !== "number";
          case "boolean":
            return typeof body[e[0]] !== "boolean";
          case "string":
            return typeof body[e[0]] !== "string";
          case "null":
            return body[e[0]] !== null;
        }
      }
    } else {
      return getInvalidFields(body[e[0]] as any, e[1]).length > 0;
    }
  });
  return invalidFields.map((a: [string, any]) => a[0]);
}
