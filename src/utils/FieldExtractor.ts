export default function FieldExtractor(
  obj: any,
  fields: string[],
  reverse: boolean = false,
): any {
  const newObj: { [key: string]: any } = {};
  for (const key in obj) {
    if (
      (fields.includes(key) && !reverse) ||
      (!fields.includes(key) && reverse)
    ) {
      newObj[key] = obj[key];
    }
  }
  return newObj;
}
