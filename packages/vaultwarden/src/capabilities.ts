/** Server capabilities with a verified disposition, rather than inferred Bitwarden cloud parity. */
export const vaultwardenCapabilities = Object.freeze({
	organizationDeviceApproval: Object.freeze({
		supported: false,
		verifiedVersions: Object.freeze(['1.36.0', '1.37.4'] as const),
		reason: 'Vaultwarden does not expose the organization SSO trusted-device approval API on the verified targets.',
	}),
});

export class UnsupportedVaultwardenCapabilityError extends Error {
	readonly code = 'UNSUPPORTED_VAULTWARDEN_CAPABILITY';
	constructor(readonly capability: 'organization-device-approval') {
		super(
			`${vaultwardenCapabilities.organizationDeviceApproval.reason} Personal auth requests are a different protocol.`,
		);
		this.name = 'UnsupportedVaultwardenCapabilityError';
	}
}
