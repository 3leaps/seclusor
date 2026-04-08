# App Note 03: Special Characters in Credentials

Some credential systems generate passwords containing characters that
have special meaning in shells, `.env` files, or JSON. This creates a
common problem: the same password is represented differently in each
format, and copying between formats without adjusting the escaping
corrupts the value.

## The Core Problem

Suppose an external system generates this password (32 characters):

```
xK9$mPq2\nR8vT+fL3wY7hJ6bN4cE1dA
```

It contains `$`, `\`, and `+`. Here is how the **same raw value** must
be represented in different formats:

### In a `.env` file

`.env` files support several quoting styles. Escaping behavior depends
on whether the value is quoted:

```env
# Double-quoted — escape sequences are processed (\$ → $, \\ → \):
DB_PASSWORD="xK9\$mPq2\\nR8vT+fL3wY7hJ6bN4cE1dA"

# Single-quoted — literal content, no escaping processed:
DB_PASSWORD='xK9$mPq2\nR8vT+fL3wY7hJ6bN4cE1dA'

# Unquoted — NO escaping processed, characters are taken literally:
DB_PASSWORD=xK9\$mPq2\\nR8vT+fL3wY7hJ6bN4cE1dA
# ⚠ This stores the backslashes as literal characters!
```

**Important**: seclusor's `import-env --dotenv-file` parser only
unescapes values inside double quotes. Unquoted values are read
literally — `\$` stays as two characters (`\` and `$`), not one.
Use double-quoted values in `.env` files for correct import.

### In a JSON string

JSON has different escaping rules. `$` has no special meaning, but `\`
must be doubled:

```json
{
  "type": "secret",
  "value": "xK9$mPq2\\nR8vT+fL3wY7hJ6bN4cE1dA"
}
```

- `$` is literal in JSON — no escaping needed
- `\\` means "literal `\`" (JSON uses `\` as escape character)
- `\n` without doubling the backslash would mean newline in JSON

### On the shell command line

```bash
# Single quotes — safest, no interpretation at all:
seclusor secrets set --key DB_PASSWORD --value 'xK9$mPq2\nR8vT+fL3wY7hJ6bN4cE1dA'

# Double quotes — $ and \ are interpreted, must be escaped:
seclusor secrets set --key DB_PASSWORD --value "xK9\$mPq2\\nR8vT+fL3wY7hJ6bN4cE1dA"
```

### Comparison table

| Format                | `$`     | `\`     | `"`                               | `!`         |
| --------------------- | ------- | ------- | --------------------------------- | ----------- |
| Raw password          | literal | literal | literal                           | literal     |
| `.env` file           | `\$`    | `\\`    | `\"` or use single-quote wrapping | literal     |
| JSON string           | literal | `\\`    | `\"`                              | literal     |
| Shell (single quotes) | literal | literal | literal                           | literal     |
| Shell (double quotes) | `\$`    | `\\`    | `\"`                              | `\!` (bash) |

## The Common Mistake

You have a working `.env` file:

```env
DB_PASSWORD=xK9\$mPq2\\nR8vT+fL3wY7hJ6bN4cE1dA
```

You copy this value into a seclusor JSON file:

```json
"value": "xK9\$mPq2\\nR8vT+fL3wY7hJ6bN4cE1dA"
```

**This is wrong.** The `\$` from the `.env` file is `.env` escaping
syntax — it means "literal `$`". But in JSON, `\$` is an invalid
escape sequence. You'll get:

```
error: json error: invalid escape at line 5 column 18
```

The correct JSON representation drops the `.env` escaping for `$`
(which JSON doesn't need) but keeps `\\` for the backslash:

```json
"value": "xK9$mPq2\\nR8vT+fL3wY7hJ6bN4cE1dA"
```

**Rule of thumb**: Never copy values between formats without
understanding which characters are escaping syntax and which are part
of the actual credential.

## The Safe Path: Use `secrets set`

`secrets set` with single quotes handles all escaping automatically:

```bash
# Paste the RAW password (from the system UI, not from a .env file):
seclusor secrets set --key DB_PASSWORD --value 'xK9$mPq2\nR8vT+fL3wY7hJ6bN4cE1dA'
```

Single quotes prevent ALL shell interpretation. Seclusor receives the
raw value and serializes it correctly to JSON internally.

If the password itself contains a single quote (`'`):

```bash
# Shell trick: end quote, add escaped quote, resume quote:
seclusor secrets set --key DB_PASSWORD --value 'it'\''s-a-password'
# Stores: it's-a-password
```

## Importing from a `.env` File

If you already have a working `.env` file, `import-env` can read it —
but **values must be double-quoted** for escape sequences to be
processed correctly:

```env
# This works — double-quoted, escapes processed:
DB_PASSWORD="xK9\$mPq2\\nR8vT+fL3wY7hJ6bN4cE1dA"

# This does NOT work — unquoted, escapes preserved literally:
DB_PASSWORD=xK9\$mPq2\\nR8vT+fL3wY7hJ6bN4cE1dA
```

```bash
seclusor secrets import-env \
  --file secrets.json \
  --dotenv-file /path/to/.env \
  --project myapp
```

If your `.env` file uses unquoted values with escape characters,
either add double quotes around the values before importing, or use
`secrets set` with single quotes instead.

## Passing via Environment Variable

If the value is already in an environment variable (set by your process
manager, CI system, or exported in your shell profile):

```bash
# The variable already holds the raw value:
seclusor secrets set --key DB_PASSWORD --value "$DB_PASSWORD"
```

**Do not `source` a `.env` file to load variables** — `source` executes
the file as shell code, which can run command substitutions or other
shell syntax. Use `secrets import-env --dotenv-file` instead, which
parses the file as data.

**Warning**: Double quotes around `"$DB_PASSWORD"` are required.
Without quotes, the shell word-splits on spaces.

## Verification

After setting a credential, verify the length matches what you expect.
The raw password length is the authoritative reference — count from the
system that generated it (web UI, API response, password manager).

```bash
# Stored value length in seclusor:
seclusor secrets get --key DB_PASSWORD --reveal | tr -d '\n' | wc -c
```

If the seclusor length is longer than the raw password, the value was
likely corrupted by pasting `.env`-escaped text (with extra backslashes)
into JSON or `secrets set`.

## Quick Reference

| I want to...            | Do this                                               |
| ----------------------- | ----------------------------------------------------- |
| Set a password with `$` | `secrets set --value 'raw$password'` (single quotes)  |
| Set a password with `\` | `secrets set --value 'raw\password'` (single quotes)  |
| Migrate from `.env`     | `secrets import-env --dotenv-file .env`               |
| Set from an env var     | `secrets set --value "$VAR"` (double quotes required) |
| Hand-edit JSON with `$` | Just type `$` — no escaping needed                    |
| Hand-edit JSON with `\` | Type `\\` — JSON requires doubled backslashes         |
| Hand-edit JSON with `"` | Type `\"` — JSON requires escaped quotes              |

## See Also

- [CLI Reference: Value vs reference](../guides/cli-reference.md) —
  `--value` and `--ref` flag documentation
- [Workflow Scenarios](../guides/scenarios/index.md) — end-to-end
  encrypted workflows
