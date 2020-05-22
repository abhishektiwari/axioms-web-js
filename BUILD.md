# Step-1 Build
Build production version,

```
npm run-script build
```

Install rollup if not already,

```
npm install rollup --global
```

Build UMD version using rollup,
```
rollup -c rollup.config.js
```

# Step-2 Publish
Increment version string in `package.json`.
```
npm publish --access public
```

# Optional - Unpublish
Unpublish a given version
```
npm unpublish @axioms/web-js@<version>
```

# Optional - NPM Linking for Local Development
First in the `web-js` root directory run,

```
cd web-js
npm link web-js @axioms/web-js
```

Then in project root directory

```
cd project
npm link web-js @axioms/web-js
```