/**
 * Whether no two values are equal. It compares hex strings, so it doesn't run in constant
 * time: use it only on public values, such as header fields and public keys.
 */
export function allDistinct(values: readonly Uint8Array[]): boolean {
  const seen = new Set<string>();
  for (const value of values) {
    const key = Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
  }
  return true;
}
