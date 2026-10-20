import js from '@eslint/js';
import parser from '@babel/eslint-parser';
export default [
	{ ignores: ['dist/**'] },
	{
		files: ['**/*.ts'],
		languageOptions: {
			parser,
			parserOptions: {
				requireConfigFile: false,
				babelOptions: {
					presets: [import.meta.resolve('@babel/preset-typescript')],
				},
			},
		},
		rules: {
			...js.configs.recommended.rules,
			'no-undef': 'off',
			'no-unused-vars': 'off',
		},
	},
];
