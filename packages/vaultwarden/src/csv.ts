/** Quoted CSV records; legacy 1Password uses backslash rather than doubled-quote escapes. */
export function parseCsv(input: string, escapeChar: '"' | '\\' = '"', delimiter = ','): string[][] {
	const rows: string[][] = [];
	let row: string[] = [];
	let field = '';
	let quoted = false;
	let closed = false;
	input = input.replace(/^\uFEFF/, '');
	for (let i = 0; i < input.length; i++) {
		const char = input[i]!;
		if (quoted) {
			if (char === escapeChar && input[i + 1] === '"') {
				field += '"';
				i++;
			} else if (char === '"') {
				quoted = false;
				closed = true;
			} else field += char;
			continue;
		}
		if (char === '"') {
			if (field || closed) throw new Error('Invalid CSV quoting.');
			quoted = true;
			continue;
		}
		if (char === delimiter) {
			row.push(field);
			field = '';
			closed = false;
			continue;
		}
		if (char === '\r' || char === '\n') {
			if (char === '\r' && input[i + 1] === '\n') i++;
			row.push(field);
			rows.push(row);
			row = [];
			field = '';
			closed = false;
			continue;
		}
		if (closed) throw new Error('Invalid CSV quoting.');
		field += char;
	}
	if (quoted) throw new Error('Unterminated CSV field.');
	if (field || row.length || closed) {
		row.push(field);
		rows.push(row);
	}
	return rows;
}
function csvCell(value: unknown): string {
	const v = value == null ? '' : String(value);
	return /[",\r\n]/.test(v) ? `"${v.replaceAll('"', '""')}"` : v;
}
export function writeCsv(rows: unknown[][]): string {
	return rows.map(row => row.map(csvCell).join(',')).join('\r\n');
}
