import { outputCommand as command, outputSuccess } from '#output';
import { arg, flag } from '@kjanat/dreamcli';
import type { VaultRuntime } from '#vault-commands';

/** Match the reference command surface and report server capability explicitly. */
export function deviceApprovalCommand(
	showHelp: (command?: string) => Promise<string>,
	runtime: VaultRuntime,
) {
	const organization = () =>
		flag.string({ pattern: /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i })
			.required().describe('Organization ID');
	const session = () => flag.string().sensitive().env('SESSION');
	const list = command('list').description('List pending organization SSO device approvals')
		.flag('organizationid', organization()).flag('session', session()).action(async ({ flags, out }) => {
			const data = await runtime.run(
				flags.session,
				false,
				vault => vault.deviceApprovals.list(flags.organizationid!),
				true,
			);
			out.json({ object: 'list', data });
		});
	const approve = command('approve').description('Approve an organization SSO device request')
		.arg('requestId', arg.string()).flag('organizationid', organization()).flag('session', session()).action(
			async ({ args, flags }) => {
				await runtime.run(
					flags.session,
					false,
					vault => vault.deviceApprovals.approve(flags.organizationid!, args.requestId),
					true,
				);
				outputSuccess();
			},
		);
	const deny = command('deny').description('Deny an organization SSO device request')
		.arg('requestId', arg.string()).flag('organizationid', organization()).flag('session', session()).action(
			async ({ args, flags }) => {
				await runtime.run(
					flags.session,
					false,
					vault => vault.deviceApprovals.deny(flags.organizationid!, args.requestId),
					true,
				);
				outputSuccess();
			},
		);
	const approveAll = command('approve-all').description('Approve all organization SSO device requests')
		.flag('organizationid', organization()).flag('session', session()).action(async ({ flags, out }) => {
			const changed = await runtime.run(
				flags.session,
				false,
				vault => vault.deviceApprovals.approveAll(flags.organizationid!),
				true,
			);
			if (changed) outputSuccess();
			else out.log('No pending device authorization requests to approve.');
		});
	const denyAll = command('deny-all').description('Deny all organization SSO device requests')
		.flag('organizationid', organization()).flag('session', session()).action(async ({ flags, out }) => {
			const changed = await runtime.run(
				flags.session,
				false,
				vault => vault.deviceApprovals.denyAll(flags.organizationid!),
				true,
			);
			if (changed) outputSuccess();
			else out.log('No pending device authorization requests to deny.');
		});
	const help = command('help').description('Show help for a device-approval command')
		.arg('command', arg.string().optional()).action(async ({ args, out }) => {
			out.log(await showHelp(args.command));
		});
	return command('device-approval').description(
		'Manage organization SSO trusted-device approval requests',
	)
		.command(list).command(approve).command(approveAll).command(deny).command(denyAll).command(help);
}
