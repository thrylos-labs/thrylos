# Vendored crypto

`noble.js` is a minified esbuild bundle of `noble.entry.js`, built from exact
pinned versions: `@noble/ed25519@2.3.0`, `@noble/hashes@1.8.0` (esbuild 0.25.0,
`--bundle --format=esm --minify --target=es2022`). It is served from the same
origin, and the page's Content-Security-Policy allows scripts only from `'self'`,
so nothing is fetched from a third-party CDN at runtime.

To rebuild: `npm i --save-exact @noble/ed25519@2.3.0 @noble/hashes@1.8.0 esbuild@0.25.0`,
then `npx esbuild noble.entry.js --bundle --format=esm --minify --target=es2022 --outfile=noble.js`.

sha256(noble.js) = db7e8b2a3cac1edd3997ac91513d2df6207a3340142a5dc5316768555a17e08d
