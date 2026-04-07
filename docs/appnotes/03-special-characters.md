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

`.env` files use shell-like escaping. `$` triggers variable expansion
and `\` is the escape character, so both must be escaped:

```env
DB_PASSWORD=xK9\$mPq2\\nR8vT+fL3wY7hJ6bN4cE1dA
```

- `\$` means "literal `$`" (the backslash is syntax, not part of the password)
- `\\` means "literal `\`" (doubled because `\` is the escape character)
- `+` needs no escaping in `.env`

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

If you already have a working `.env` file, `import-env` reads values
after `.env` unescaping and stores them correctly:

```bash
seclusor secrets import-env \
  --file secrets.json \
  --dotenv-file /path/to/.env \
  --project myapp
```

This is the safest migration path — the `.env` parser handles the
format-specific escaping and seclusor receives the raw values.

## Passing via Environment Variable

If the value is already loaded in an environment variable:

```bash
# Source the .env first (the shell resolves \$ to $):
source /path/to/.env

# The variable now holds the raw value:
seclusor secrets set --key DB_PASSWORD --value "$DB_PASSWORD"
```

**Warning**: Double quotes around `"$DB_PASSWORD"` are required.
Without quotes, the shell word-splits on spaces.

## Verification

After setting a credential, verify the length matches your source:

```bash
# Stored value length:
seclusor secrets get --key DB_PASSWORD --reveal | tr -d '\n' | wc -c

# .env source length (after unescaping):
grep '^DB_PASSWORD=' .env | sed 's/^DB_PASSWORD=//' | tr -d '\n' | wc -c
```

**Note**: The `.env` length includes escape characters, so it may be
longer than the stored value. If the seclusor length is _longer_ than
expected, you likely pasted `.env`-escaped text into JSON.

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
