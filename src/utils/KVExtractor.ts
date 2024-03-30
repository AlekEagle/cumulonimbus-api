// Extracts values from an object based on a list of keys.

export default function KVExtractor<T extends any>(
  obj: T,
  fields: Array<keyof T>,
  omitSelection: boolean = false,
): any {
  const newObj: { [key: string]: any } = {};
  for (const key in obj) {
    if (
      (fields.includes(key) && !omitSelection) ||
      (!fields.includes(key) && omitSelection)
    ) {
      newObj[key] = obj[key];
    }
  }
  return newObj;
}
