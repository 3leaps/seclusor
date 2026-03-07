# TypeScript bindings

N-API addon bindings for seclusor.

## Local workflow

```bash
npm install
npm run build
npm test
```

The build compiles the native Rust addon and writes a platform-specific `.node`
artifact under `native/`.
