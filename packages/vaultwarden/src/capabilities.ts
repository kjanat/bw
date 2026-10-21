/** Server capabilities with a verified disposition, rather than inferred Bitwarden cloud parity. */
export const vaultwardenCapabilities = Object.freeze({
	organizationDeviceApproval: Object.freeze({
		supported: false,
		verifiedVersions: Object.freeze(['1.36.0', '1.37.4'] as const),
		reason: 'Vaultwarden does not expose the organization SSO trusted-device approval API on the verified targets.',
	}),
	cipherTypes: Object.freeze({
		minimumVersions: Object.freeze({
			6: '1.37.4',
			7: '1.37.4',
			8: '1.37.4',
		}),
	}),
});

const cipherTypeNames: Record<number, string> = {
	6: 'bank account',
	7: "driver's license",
	8: 'passport',
};

function versionParts(version: string): [number, number, number, boolean] | undefined {
	const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(version);
	if (!match) return undefined;
	return [Number(match[1]), Number(match[2]), Number(match[3]), match[4] !== undefined];
}

export function isVaultwardenVersion(version: string): boolean {
	return versionParts(version) !== undefined;
}

export function vaultwardenVersionAtLeast(version: string, minimum: string): boolean {
	const actual = versionParts(version), required = versionParts(minimum);
	if (!actual || !required) return false;
	for (let i = 0; i < 3; i++) {
		if (actual[i]! !== required[i]!) return actual[i]! > required[i]!;
	}
	return !actual[3] || required[3]!;
}

export function minimumVaultwardenVersionForCipherType(type: number): string | undefined {
	return vaultwardenCapabilities.cipherTypes
		.minimumVersions[type as keyof typeof vaultwardenCapabilities.cipherTypes.minimumVersions];
}

export class UnsupportedVaultwardenCapabilityError extends Error {
	readonly code = 'UNSUPPORTED_VAULTWARDEN_CAPABILITY';
	constructor(
		readonly capability: 'organization-device-approval' | 'cipher-type',
		options: { itemType?: number; minimumVersion?: string; serverVersion?: string } = {},
	) {
		const reason = capability === 'organization-device-approval'
			? `${vaultwardenCapabilities.organizationDeviceApproval.reason} Personal auth requests are a different protocol.`
			: `${
				cipherTypeNames[options.itemType!] ?? `Item type ${options.itemType}`
			} requires Vaultwarden ${options.minimumVersion} or newer; this server reports ${options.serverVersion}.`;
		super(reason);
		this.name = 'UnsupportedVaultwardenCapabilityError';
	}
}
