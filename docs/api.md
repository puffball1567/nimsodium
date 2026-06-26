# API Documentation

Generate local API documentation with:

```sh
nim doc --project --index:on --outdir:htmldocs --path:src src/nimsodium.nim
nim doc --outdir:htmldocs --path:src src/nimsodium/advanced.nim
```

The generated documentation is written to `htmldocs/`.
