import { type JsonObject, object, text } from '#client';

export interface ApplicableOrganizationPolicy {
	policy: JsonObject;
	organization?: JsonObject;
}

function sameId(left: unknown, right: unknown): boolean {
	return typeof left === 'string' && typeof right === 'string' && left.toLowerCase() === right.toLowerCase();
}

function appliesToOrganizationMember(organization: JsonObject): boolean {
	return (organization.status === 1 || organization.status === 2)
		&& organization.enabled === true
		&& organization.usePolicies === true
		&& organization.type !== 0
		&& organization.type !== 1
		&& organization.isProviderUser !== true;
}

/** Resolve policy membership using the same exemptions as Bitwarden's SDK. */
export function applicableOrganizationPolicies(snapshot: JsonObject, type: number): ApplicableOrganizationPolicy[] {
	const profile = object(snapshot.profile);
	const organizations = Array.isArray(profile.organizations) ? profile.organizations.map(object) : [];
	const policies = [
		...(Array.isArray(snapshot.policies) ? snapshot.policies : []),
		...(Array.isArray(snapshot.policiesNew) ? snapshot.policiesNew : []),
	].map(object);
	return policies.flatMap(policy => {
		if (policy.type !== type || policy.enabled !== true) return [];
		const organization = organizations.find(value => sameId(value.id, text(policy.organizationId)));
		// The SDK errs on the side of enforcement when policy context has not synced yet.
		if (organization && !appliesToOrganizationMember(organization)) return [];
		return [{ policy, ...(organization ? { organization } : {}) }];
	});
}
