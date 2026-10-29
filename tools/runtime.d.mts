export const repoRoot: string;
export function runDirect(prefix: string[], source: string, operations: Record<string, unknown>): Promise<void>;
export function inDirectory<T>(directory: string, action: () => Promise<T>): Promise<T>;
export function resolveWasmOpt(requested?: string): string;
