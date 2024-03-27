export default function isType<T>(
  value: any,
  validatingKeys: (keyof T)[],
): value is T {
  return validatingKeys.every((key) => value[key] !== undefined);
}
