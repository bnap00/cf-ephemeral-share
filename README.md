# ephemeral sharing

Self-hosted, expiring file and text sharing on Cloudflare Workers. Files are
encrypted in the browser before upload. The Worker stores ciphertext in R2 and
keeps expiry and download-count metadata in KV.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/bnap00/cf-ephemeral-share)

There is no application build step and no runtime package dependency. The
deployed application is a Worker plus the static files in `public/`.

## What it protects

The browser encrypts each upload with AES-256-GCM. The decryption key stays in
the URL fragment, as in `/f/abc#key`. Browsers do not send URL fragments to the
server.

| Data | Visible to the server |
| --- | --- |
| File contents | No, R2 stores ciphertext |
| Filename and media type | No, they are in the encrypted header |
| File size, expiry, and download count | Yes |

The share link is a secret. Anyone who has it can decrypt the file while the
link remains active. Send it through a channel you trust.

An optional password adds a second factor. The browser derives the encryption
key from both the link key and the password, so neither is enough on its own.
The server never receives the password.

Browser encryption cannot protect against a compromised deployment serving
modified JavaScript. Self-host the Worker and review changes before deploying
them. The command-line client in `tools/ef.mjs` is available when you do not
want to use code served by the site.

## Deploy to Cloudflare

The button above creates a copy of this repository in your GitHub or GitLab
account and deploys it with Workers Builds. Cloudflare provisions the R2 bucket
and KV namespace declared in `wrangler.toml`, then replaces the placeholder
resource values in your new repository.

When Cloudflare asks for `UPLOAD_TOKEN`, provide a long random value. You can
generate one locally with:

```sh
npm run token
```

Uploading fails closed. If `UPLOAD_TOKEN` is missing, the site can serve
existing links but cannot accept uploads.

The default deployment uses a `workers.dev` address. Add a custom domain in the
Cloudflare dashboard after the first deployment if you want one.

## Manual deployment

Install the development dependencies and authenticate Wrangler:

```sh
npm install
npx wrangler login
```

Create the storage resources:

```sh
npx wrangler r2 bucket create ephemeral-files
npx wrangler kv namespace create META
```

Paste the KV namespace ID from the second command into `wrangler.toml`, replacing
`00000000000000000000000000000000`. If you choose a different R2 bucket name,
update `bucket_name` in the same file.

Create the upload secret and deploy:

```sh
npm run token
npx wrangler secret put UPLOAD_TOKEN
npm run deploy
```

Do not put the token in `wrangler.toml`. Production secrets belong in Wrangler
or the Cloudflare dashboard. Local secrets belong in `.dev.vars`, which Git
ignores.

For individual accounts, the shared upload token is usually enough. For team
access, put Cloudflare Access in front of `/` and `/api/upload/*`. Leave `/f/*`,
`/api/f/*`, and `/api/d/*` public so recipients can open links. Keep the upload
token as a second check.

## Use

Open the deployed site and enter the upload token. Drop one or more files, or
switch to the Text tab. Choose an expiry, a download limit, and an optional
password. The browser encrypts the content and returns a share link.

The site is installable as a PWA. Installed mode can remember the upload token
on that device. A normal browser tab keeps it for the current session unless
you select "Remember on this device."

### Text shares

Text shares are useful for an `.env`, an API key, a connection string, or a
short note. They default to one read. The recipient must press "Reveal text"
before the browser fetches the ciphertext, so link previews from chat tools do
not spend the read.

After decryption, the page offers Copy and Save as file. The recipient can keep
anything they reveal. Expiry and read limits control access to the service, not
what a recipient does afterward.

### Multiple files

A multi-file upload creates one encrypted object per file and a small encrypted
index. The share link points to the index. Recipients can download files one at
a time or download the full set. Revoking the bundle removes the index and all
of its member objects.

### Command-line client

Set the deployment URL and upload token, then use `tools/ef.mjs`:

```sh
export EF_HOST=https://files.example.com
export EF_TOKEN=your-upload-token

node tools/ef.mjs put ./backup.tar.gz --ttl 3600 --limit 1 --password hunter2
node tools/ef.mjs get 'https://files.example.com/f/abc#key' -o ./backup.tar.gz -p hunter2

node tools/ef.mjs put - --name .env --limit 1 < .env
node tools/ef.mjs get 'https://files.example.com/f/abc#key' > .env
```

Text shares print to standard output. A plain `curl` request to `/api/d/<id>`
returns ciphertext because the decryption key is in the share link fragment.

## Configuration

| Setting | Location | Default |
| --- | --- | --- |
| Per-file size cap | `MAX_SIZE_MB` in `wrangler.toml` | 5120 MiB |
| Expired-object sweep | `crons` in `wrangler.toml` | Hourly |
| Per-IP rate limits | `[[ratelimits]]` in `wrangler.toml` | Disabled |
| Upload access | Wrangler secret `UPLOAD_TOKEN` | Uploads disabled |
| Brand name | `BRAND_NAME` in `wrangler.toml` | `ephemeral` |
| Tagline | `BRAND_TAGLINE` in `wrangler.toml` | Built-in encryption tagline |
| Footer | `BRAND_FOOTER` in `wrangler.toml` | Built-in encryption note |
| Logo | `BRAND_LOGO` in `wrangler.toml` | None |
| Accent colors | `BRAND_ACCENT`, `BRAND_ACCENT_DARK` in `wrangler.toml` | Blue |

The UI offers expiry periods from 10 minutes to 30 days and download limits
from one read to unlimited. The Worker enforces both.

The optional rate-limit examples in `wrangler.toml` need namespace IDs unique
to your Cloudflare account. Uncomment them only after choosing those IDs.

### Branding

Uncomment the `BRAND_*` values in `wrangler.toml` and deploy again. The name,
tagline, footer, logo, and light/dark accent colors apply to both the upload page
and shared links. Set `BRAND_TAGLINE` or `BRAND_FOOTER` to an empty string to
hide it.

`BRAND_LOGO` must point to a file committed under `public/`, for example
`/acme-logo.svg`. External logo URLs are rejected so the existing content
security policy stays strict. Accent colors must use six-digit hex notation.
The interface picks black or white button text based on each accent color.

The browser tab title changes at runtime. To brand the installed PWA too, edit
`public/manifest.webmanifest`, replace the icon files under `public/icons/`, and
update `public/favicon.svg`.

## How encryption works

The browser splits plaintext into 8 MiB chunks and seals each chunk separately.
Uploads use R2 multipart upload with one part per encrypted chunk.

```text
key      HKDF-SHA256(link key + PBKDF2-SHA256(password, 600k), salt)
header   salt + nonce base + GCM(filename, type, size, chunk count) -> KV
body     GCM(chunk 0) + GCM(chunk 1) + ...                         -> R2
nonce    nonce base + u32be(chunk index)
aad      u32be(chunk index) + final-chunk flag
```

The chunk index and final-chunk flag are authenticated data. Reordering,
dropping, duplicating, or moving chunks between files causes authentication to
fail. The encrypted header records the expected chunk count, which catches
truncation.

The Worker compares upload tokens in constant time. It bounds multipart part
sizes and counts against the declared file size. Downloads use
`application/octet-stream`, attachment disposition, and a sandboxed content
security policy, so uploaded content is not served as HTML or script. Unknown
paths return 404 instead of the application shell.

For a one-read share, the Worker deletes the KV record before streaming the R2
object and leaves a tombstone for the scheduled sweep. This prevents a cleanup
job from deleting bytes during an active response.

## Local development and tests

Create `.dev.vars` with a local token before starting Wrangler:

```dotenv
UPLOAD_TOKEN=test-token-do-not-use-in-production
```

Run the local Worker:

```sh
npm run dev
```

The crypto tests do not need a Worker:

```sh
npm test
```

The browser test expects the local Worker at `http://127.0.0.1:8787` and the
test token shown above:

```sh
node test/ui.mjs
```

Set `CHROMIUM=/path/to/chrome` to use an existing Chromium installation.

## Known limits

- Download counting uses a read-modify-write operation in KV. Two simultaneous
  requests for a one-read link may both succeed. Treat the limit as a guardrail,
  not a lock.
- Browsers without the File System Access API assemble the decrypted file in a
  Blob before saving it.
- The Worker holds one encrypted chunk in memory for each active multipart part.

## Self Promotion

*Put together with ❤️ by [Bharat Parsiya](https://bnap.dev/)*


## License

[MIT](LICENSE)
