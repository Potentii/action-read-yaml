import {defineConfig} from 'vite'

// https://vitejs.dev/config/
export default defineConfig({
	build: {
		lib: {
			entry: './src/index.mjs',
			formats: [ 'system' ],
			name: 'ReadYaml',
			fileName: 'index',
		},
		target: 'es2022'
	},
});
