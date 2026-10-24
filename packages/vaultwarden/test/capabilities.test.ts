import { expect, test } from 'bun:test';
import { isVaultwardenVersion, vaultwardenVersionAtLeast } from '#capabilities';

test('Vaultwarden capability versions follow SemVer prerelease ordering', () => {
	expect(vaultwardenVersionAtLeast('1.37.4-rc.2', '1.37.4')).toBe(false);
	expect(vaultwardenVersionAtLeast('1.37.4', '1.37.4-rc.2')).toBe(true);
	expect(vaultwardenVersionAtLeast('1.37.4-rc.10', '1.37.4-rc.2')).toBe(true);
	expect(vaultwardenVersionAtLeast('1.37.4-rc.2', '1.37.4-rc.10')).toBe(false);
	expect(vaultwardenVersionAtLeast('1.37.4-2', '1.37.4-rc')).toBe(false);
	expect(vaultwardenVersionAtLeast('1.37.4-rc', '1.37.4-2')).toBe(true);
	expect(vaultwardenVersionAtLeast('1.37.4-rc', '1.37.4-rc.1')).toBe(false);
	expect(vaultwardenVersionAtLeast('1.37.4-rc.1', '1.37.4-rc')).toBe(true);
	expect(isVaultwardenVersion('1.37.4-01')).toBe(false);
	expect(isVaultwardenVersion('01.37.4')).toBe(false);
	expect(isVaultwardenVersion('1.37.4+build.7')).toBe(true);
	expect(isVaultwardenVersion('1.37.4+build..7')).toBe(false);
	expect(vaultwardenVersionAtLeast('9007199254740993.0.0', '9007199254740992.0.0')).toBe(true);
});
