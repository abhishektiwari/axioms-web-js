import resolve from '@rollup/plugin-node-resolve';
import babel from '@rollup/plugin-babel';
import json from '@rollup/plugin-json';
import commonjs from '@rollup/plugin-commonjs';

export default {
    input: 'src/index.js',
    plugins: [
        resolve({
            browser: true,
            customResolveOptions: {
                moduleDirectory: 'node_modules'
            }
        }),
        commonjs({
            include: 'node_modules/**'
        }),
        json(),
        babel({ babelHelpers: 'bundled' })
    ],
    output: {
        file: 'dist/bundle.js',
        format: 'cjs'
    },
    external: ['lodash']
};