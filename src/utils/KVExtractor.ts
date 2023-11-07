// Extracts values from an object based on a list of keys.

export default function KVExtractor(
  obj: any,
  fields: string[],
  invertSelection: boolean = false,
): any {
  const newObj: { [key: string]: any } = {};
  for (const key in obj) {
    if (
      (fields.includes(key) && !invertSelection) ||
      (!fields.includes(key) && invertSelection)
    ) {
      newObj[key] = obj[key];
    }
  }
  return newObj;
}
