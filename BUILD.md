# Step-1 Build
Build production version,

```
npm run-script build
```

# Step-2 Publish
Increment version string in `package.json`.
```
npm publish --access public
```

# Optional Unpublish
Unpublish a given version
```
npm unpublish @axioms/web-js@<version>
```