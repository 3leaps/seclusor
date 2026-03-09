# Storage Codecs

Seclusor supports two storage codecs:

- `bundle`: encrypts the whole document into one age payload.
- `inline`: encrypts per-value while keeping the document mostly diff-friendly.

## Bundle

Use when you want strongest accidental-leak resistance and simple operational handling.

## Inline

Use when you need git diffs and partial merge ergonomics. Values are prefixed with `sec:age:v1:`.

## Convert

Use `seclusor secrets convert` to translate between bundle and inline formats.
