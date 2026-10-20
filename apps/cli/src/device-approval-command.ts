import { outputCommand as command } from '#output';
import { arg, flag } from '@kjanat/dreamcli';
import { UnsupportedVaultwardenCapabilityError } from '@kjanat/vaultwarden';

/** Preserve the reference command surface with an explicit server-capability disposition. */
export function deviceApprovalCommand() {
	const organization = () =>
		flag.string({ pattern: /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i })
			.required().describe('Organization ID');
	const session = () => flag.string().sensitive().env('VW_SESSION');
	const unsupported = (): never => {
		throw new UnsupportedVaultwardenCapabilityError('organization-device-approval');
	};
	const list = command('list').description('List pending organization SSO device approvals')
		.flag('organizationid', organization()).flag('session', session()).action(unsupported);
	const approve = command('approve').description('Approve an organization SSO device request')
		.arg('requestId', arg.string()).flag('organizationid', organization()).flag('session', session()).action(
			unsupported,
		);
	const deny = command('deny').description('Deny an organization SSO device request')
		.arg('requestId', arg.string()).flag('organizationid', organization()).flag('session', session()).action(
			unsupported,
		);
	const approveAll = command('approve-all').description('Approve all organization SSO device requests')
		.flag('organizationid', organization()).flag('session', session()).action(unsupported);
	const denyAll = command('deny-all').description('Deny all organization SSO device requests')
		.flag('organizationid', organization()).flag('session', session()).action(unsupported);
	return command('device-approval').description(
		'Organization SSO device approvals (unsupported by verified Vaultwarden targets)',
	)
		.command(list).command(approve).command(deny).command(approveAll).command(denyAll);
}
