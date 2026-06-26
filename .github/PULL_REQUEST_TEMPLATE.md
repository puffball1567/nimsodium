## Summary

Describe the change and the workflow it affects.

## Checklist

- [ ] I did not expose raw libsodium APIs as public API.
- [ ] I added or updated tests for success and failure paths.
- [ ] I updated `AUDIT.md` if a new libsodium symbol is used.
- [ ] I updated `docs/workflows.md` for new user-facing workflows.
- [ ] I updated `docs/formats.md` for stored format changes.
- [ ] I updated `CHANGELOG.md` for user-visible changes.

## Security-sensitive Changes

If this changes cryptographic API shape, binary formats, nonce/salt/tag
handling, key derivation, raw FFI, authentication failure behavior, or file
output replacement behavior, explain the rationale and tests here.
