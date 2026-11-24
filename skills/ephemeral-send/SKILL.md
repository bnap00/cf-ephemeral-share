---
name: ephemeral-send
description: Hand a person a secret (password, API key, token, .env, private key, connection string) or a sensitive file through the configured ephemeral share host, encrypted to the person's receiving key so the link is useless to you, your logs and the transcript. Use whenever you would otherwise paste a credential or sensitive file into chat, or a person asks you to send/share/hand over a secret or file securely. You never read, print or type the content.
---

# ephemeral-send

`ef send` encrypts a file or secret locally, uploads only ciphertext to the
person's self-hosted ephemeral deployment, and seals the decryption key to a
**receiving key** whose private half lives only in the person's browser. You
get back a link that you can show in chat: without that browser it opens
nothing, and on a deployment that enforces download keys it cannot even spend
the one read.

Run every command through `scripts/ef.sh` (in this skill's directory). It
finds the CLI via `$EF_CLI` or `ef` on `PATH`. Below, `EF` means that script's
path.

## Rules (do not bend these)

1. **Never look at the content.** Do not `cat`, `head`, `less`, `Read`,
   `grep`, `echo` or otherwise display the secret or the file, before or after
   sending. Pass the path or pipe the bytes straight into `ef send`.
2. **Never put a secret on a command line.** No `--text`, no `--password`, no
   secret inside a command string you write. `ef send` refuses `--text` and
   `--password`. Use a file path, stdin (`-`), `--from-env VAR`, or
   `--generate N`.
3. **Never pipe a secret anywhere you can see it.** Its only destination is
   `ef send` (and, when generating a credential, the system that must store
   it). No `tee` to the terminal, no `set -x`, no `2>&1` from a command that
   might print it.
4. **Never send unsealed** (`--unsealed`) unless the person explicitly asks
   for a plain link after being told anyone who sees it can open it.
5. **Never ask the person to paste a secret, the upload token, or a private
   key into chat.** Public receiving keys (`efpk1.…`) are fine to paste.
6. Report only what `ef send` prints: the link, expiry, read limit,
   recipient. Never paraphrase, hint at or summarise the content.

## 1. Check the setup

```sh
EF config show        # host and whether a token is set (token is redacted)
EF recipient list     # receiving keys; one is marked (default)
```

- **No host or token:** the person sets them up themselves. Tell them to run:
  ```sh
  ef config set host https://their-share-host
  ef config set token - < /path/to/token.txt   # never on the command line
  ```
  Do not offer to handle the token for them.
- **No recipient:** ask the person to open `https://<host>/keys` in the
  browser they will open the link in, create a receiving key, and either run
  the `ef recipient add …` line it shows, or paste the `efpk1.…` public key to
  you. Then run `EF recipient add <name> efpk1.…` (public keys are not
  secret). The first one added becomes the default.

## 2. Send

Add `--json` to get a machine-readable result:
`{"link","id","sealed","recipients","kind","size","downloads","expires","deleteToken"}`.

| What | Command |
| --- | --- |
| A file on disk | `EF send ./path/to/file --json` |
| A directory | `d="$(mktemp -d)" && tar czf "$d/dir.tgz" -C parent dir && EF send "$d/dir.tgz" --json; s=$?; rm -rf "$d"; [ "$s" -eq 0 ]` |
| Output of a command | `some-command 2>/dev/null \| EF send - --name db.env --json` |
| An environment variable | `EF send --from-env DATABASE_URL --name database-url --json` |
| A new random secret only they will see | `EF send --generate 32 --name new-api-secret --json` |

Options: `--to <name|efpk1…>` (repeatable, default: the configured default
recipient), `--name <shown filename>`, `--limit <reads>` (default **1**, `0` =
unlimited), `--ttl <seconds>` (default 86400, max 30 days).

**A credential you create and also configure somewhere** (rotate a DB
password, mint a token): keep it in a shell variable for one command, feed it
to both destinations through stdin, and unset it, all in one shell call with
no output of the value:

```sh
secret="$(openssl rand -base64 32)" \
  && printf %s "$secret" | some-admin-cli set-password --user app --password-stdin \
  && printf %s "$secret" | EF send - --name app-db-password --json; \
  unset secret
```

If the target tool only takes the secret as an argument, stop and tell the
person; do not put it on a command line.

## 3. Hand over

Tell the person, in one or two lines:

- the link,
- that it opens only in the browser holding receiving key `<name>`,
- how many reads it allows and when it expires (a 1-read link dies once revealed).

Keep `link` and `deleteToken` from the JSON. If the person says it went to
the wrong place, or no longer needs it, revoke it (the link carries the host):

```sh
EF rm '<link>' --token <deleteToken>
```

## Errors

| Message | Meaning / action |
| --- | --- |
| `no receiving key configured` | Step 1, no recipient. |
| `no upload token configured` | Step 1, no token; the person sets it. |
| `refusing to send the upload token … over plain http` | Host is not https. Tell the person; do not work around it. |
| `unknown recipient 'x'` | Use a name from `EF recipient list`. |
| `… is a directory` | Archive it first (table above). |
| `ef CLI not found` | The person installs it: `npm install -g github:bnap00/cf-ephemeral-share`, or sets `EF_CLI=/path/to/tools/ef.mjs`. |
| `upload … 401` | The configured token is wrong or rotated; the person updates it. |
