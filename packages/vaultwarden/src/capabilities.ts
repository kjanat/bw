/** Server capabilities with a verified disposition, rather than inferred Bitwarden cloud parity. */
export const vaultwardenCapabilities = Object.freeze({
	fileUploads: Object.freeze({
		maximumEncryptedBytes: 550_502_400,
	}),
	collectionlessOrganizationItems: Object.freeze({
		fullAccessRequiredFrom: '1.37.4',
	}),
	organizationImportCollectionAccess: Object.freeze({
		preflightRequiredFrom: '1.37.4',
	}),
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

interface VaultwardenVersion {
	core: [string, string, string];
	prerelease?: string[];
}

function versionParts(version: string): VaultwardenVersion | undefined {
	const match =
		/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/
			.exec(version);
	if (!match) return undefined;
	const prerelease = match[4]?.split('.');
	if (
		prerelease?.some(part =>
			!part || !/^[0-9A-Za-z-]+$/.test(part) || (/^\d+$/.test(part) && part.length > 1 && part[0] === '0')
		)
	) {
		return undefined;
	}
	return { core: [match[1]!, match[2]!, match[3]!], prerelease };
}

export function isVaultwardenVersion(version: string): boolean {
	return versionParts(version) !== undefined;
}

export function vaultwardenVersionAtLeast(version: string, minimum: string): boolean {
	const actual = versionParts(version), required = versionParts(minimum);
	if (!actual || !required) return false;
	for (let i = 0; i < 3; i++) {
		if (actual.core[i] !== required.core[i]) {
			return actual.core[i]!.length !== required.core[i]!.length
				? actual.core[i]!.length > required.core[i]!.length
				: actual.core[i]! > required.core[i]!;
		}
	}
	if (!actual.prerelease) return true;
	if (!required.prerelease) return false;
	for (let i = 0; i < Math.max(actual.prerelease.length, required.prerelease.length); i++) {
		const left = actual.prerelease[i], right = required.prerelease[i];
		if (left === undefined) return false;
		if (right === undefined) return true;
		if (left === right) continue;
		const leftNumeric = /^\d+$/.test(left), rightNumeric = /^\d+$/.test(right);
		if (leftNumeric && rightNumeric) return left.length !== right.length ? left.length > right.length : left > right;
		if (leftNumeric !== rightNumeric) return !leftNumeric;
		return left > right;
	}
	return true;
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
