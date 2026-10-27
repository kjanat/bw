/** Vaultwarden 1.36 returns a JSON string; newer releases return the JWT as plain text. */
export async function registrationVerificationToken(response: Response): Promise<string> {
	const body = (await response.text()).trim();
	try {
		const parsed: unknown = JSON.parse(body);
		if (typeof parsed === 'string' && parsed.length > 0) return parsed;
	} catch {
		if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(body)) return body;
	}
	throw new Error('Invalid registration verification response.');
}
