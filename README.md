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
| Which files of a password-protected bundle belong together | Yes, they share a key-derivation salt |
| A hash of the download key derived from the link key | Yes, to check downloads; it reveals nothing about the encryption key |

The encrypted header is padded to a multiple of 256 bytes, so its length does
not reveal the length of the filename.

The share link is a secret. Anyone who has it can decrypt the file while the
link remains active. Send it through a channel you trust.

An optional password adds a second factor. The browser derives the encryption
key from both the link key and the password, so neither is enough on its own.
The server never receives the password.

Shares uploaded by current clients are also bound to their link key on the
server. A download proves it holds the link key without sending it, so a share
ID alone cannot spend a one-read link once the deployment enforces this. See
[Key-bound downloads](#key-bound-downloads).

Agents and scripts can send to a person too, sealed to a receiving key that
only that person's browser holds. The link they print is then useless to
them, their logs, and any transcript it appears in. See
[Sending from agents](#sending-from-agents).

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
existing links but cannot accept uploads, and interrupted downloads of limited
shares cannot resume.

The default deployment uses a `workers.dev` address. Add a custom domain in the
Cloudflare dashboard after the first deployment if you want one.

## Manual deployment

Install the development dependencies from the lockfile and authenticate
Wrangler:

```sh
npm ci
npx wrangler login
```

The project uses npm. `.npmrc` sets `min-release-age=3`, so npm 11.10 or later
will not resolve package versions published in the last three days. Older npm
versions ignore the setting with a warning.

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

Production deployments that keep their own settings in an untracked
`wrangler.deploy.toml` can deploy with `npm run deploy:prod`, which runs
`wrangler deploy -c wrangler.deploy.toml`.

### Cloudflare Access

For individual accounts, the shared upload token is usually enough. For team
access you can add Cloudflare Access. Keep the upload token as a second check.

Recipients load the same single-page app as the uploader, so protecting the
whole hostname locks them out. Protect only these paths:

- `/`, the upload page, so there is a page where users sign in
- `/api/upload/*`
- `/api/auth`

Add a bypass policy for everything a recipient's browser loads:

- `/f/*`, `/keys`, `/api/f/*`, `/api/d/*`, and `/api/config`
- `/app.js`, `/crypto.js`, `/upload.js`, `/keys.js`, `/style.css`, and `/sw.js`
- `/manifest.webmanifest`, `/favicon.svg`, and `/icons/*`
- the `BRAND_LOGO` path, if you set one

`DELETE /api/f/<id>` (revoke) needs the share's delete token, so it can stay
public. Test the rules in a private window with a real share link before you
rely on them. The command-line client cannot send Access service-token headers,
so it stops working once `/api/upload/*` is protected.

## Use

Open the deployed site and enter the upload token. Drop one or more files, or
switch to the Text tab. Choose an expiry, a download limit, and an optional
password. The browser encrypts the content and returns a share link.

The site is installable as a PWA. Installed mode can remember the upload token
on that device. A normal browser tab keeps it for the current session unless
you select "Remember on this device." The lock button can forget the token
alone, or the token together with the list of recent links.

The service worker loads the app files from the network first and uses its
cache only when the network fails or takes longer than three seconds. Open
tabs and installed PWAs pick up a new deployment the next time they load
online. Share pages and `/api/*` requests always go to the network.

The page rejects folders and files over the size cap before it encrypts
anything. Zip a folder before sharing it. A failed or cancelled upload is
aborted on the server. For a multi-file upload, the browser also deletes the
files it had already uploaded.

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
a time or download the full set.

The file list counts as a read. If a bundle has a download limit, the recipient
must press "Show files" before the browser fetches it, so link previews do not
spend it. Bundles without a limit show the list when the page loads.

Where the browser supports it, "Download all" asks for a folder once. It never
overwrites an existing file. Other browsers save each file the same way as a
single download, described below.

Revoking a bundle from the uploading browser's recent list removes the index
and all of its files, because only that browser holds the files' delete
tokens. The server revokes one ID at a time. If an index expires or is burned
first, its files stay until their own expiry.

### Large and interrupted downloads

Where the browser has a save picker, the page asks where to save the file and
streams the decrypted chunks straight into it. Without one, the page writes the
file to a temporary entry in the browser's origin private file system (OPFS),
then hands the finished, disk-backed file to the browser's downloader. The
temporary entry is deleted ten minutes after the hand-off. Closing the page
during a download tries to delete the partial entry straight away. Anything a
closed or crashed tab left behind is removed the next time a page of this
deployment loads in that browser: a finished file fifteen minutes after its
hand-off, a partial one an hour after it was last written. Until then the
decrypted file sits in browser storage as well as in your downloads folder,
readable by anyone who uses the same browser profile.

The page falls back to holding the file in memory when:

- the browser's OPFS cannot write files as streams, as in older Safari
  releases, or OPFS is blocked, as in some private windows
- the browser reports too little free storage before the download starts
- storage runs out partway through. The page then starts the file again in
  memory under the same download, or stops and asks you to free disk space if
  it cannot do that without spending another download

The memory path asks for confirmation before holding more than 1 GiB, and the
prompt says why the file could not go to disk.

If the connection drops, the page and `ef get` continue from the first chunk
that has not verified yet, with up to five reconnects in a row and growing
pauses between them. A resume never spends another download. Each counted
download comes with a resume ticket, and a ranged request that carries one is
served without counting. A ticket lasts about ten minutes, so during a long
download of a limited share the client renews it every four minutes. A chain
of renewed tickets ends six hours after the counted download, or ten minutes
after the share expires, whichever comes first. It also ends after eight
renewals or resumes in a row that do not start at least one chunk further into
the file than before.

A burned one-read link can be resumed until the sweep removes its object,
which happens no sooner than ten minutes after the burn. Without a usable
ticket, a dropped download of a limited share stops with an error instead of
retrying, because a new request would spend another download. Unlimited
shares resume with a plain range request. A chunk that fails verification is
never retried. A deployment without `UPLOAD_TOKEN` issues no tickets, so only
its unlimited shares resume.

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
On a deployment that enforces download keys, it gets a 401 response instead
for shares that have a download verifier.

The client handles single files, text, and multi-file shares, which it saves
into the directory given with `-o`. It retries share lookups, uploads and
revokes. It never repeats a counted download, because that may spend a second
view, but it resumes a dropped one under its resume ticket as the browser
does. A password passed with `--password` is visible to other users of the
same machine in the process list; use `--password-stdin` or `EF_PASSWORD`
instead.

`put` registers a download verifier, as the browser does, and `get` sends the
download key. Older copies of the client do neither. On a deployment that sets
`DOWNLOAD_AUTH = "enforce"`, an older `get` receives a 401 response for every
share that has a verifier. Nothing is spent.

#### Changes for scripts that used older copies of `ef`

The current client checks its flags before anything is uploaded or
downloaded. A server that predates it is not affected. Values the Worker has
always adjusted are adjusted the same way, with a warning on standard error:
a `--ttl` under 60 becomes 60, one over 30 days becomes 30 days, and
fractions of `--ttl` or `--limit` are cut to whole numbers (`--limit 1.5` is
1). The following are now refused with exit code 1, where older copies
quietly picked a default:

- an empty, non-numeric, zero or negative `--ttl` (it used to mean one day)
- an empty, non-numeric or negative `--limit`, or one between 0 and 1 (it
  used to mean unlimited). Use `--limit 0` for unlimited.
- an empty `--password` or `EF_PASSWORD` (it used to mean no password)
- a value flag such as `--ttl` given last with no value after it

`ef get` without `-o` no longer overwrites an existing file of the share's
name when standard error is a terminal; it stops and asks for `-o` or
`--force`. Without a terminal, as in scripts, it still overwrites, with a
warning. Members of a multi-file share are never overwritten without
`--force`.

`put` prints the delete token to standard error. To revoke a share without the
browser:

```sh
curl -X DELETE -H 'x-delete-token: <delete token>' https://files.example.com/api/f/<id>
```

### Sending from agents

Human-to-human links carry their key in the fragment, so whoever sees the
link can open it. That is the wrong shape when the sender is an AI agent: its
commands and output are kept in transcripts and provider logs. Agent-to-human
shares instead seal the link key to a **receiving key** that only the
recipient's browser holds.

1. The recipient opens `https://<host>/keys` in the browser they will read
   sealed links in, and presses "Create receiving key". The browser creates
   an ECDH P-256 key pair, keeps the private half in IndexedDB as a
   non-extractable key, and shows the public half (`efpk1.…`). No upload
   token is needed for this page. One key per device or browser profile.
2. Where the agent runs, the person configures the CLI once. The upload token
   is read from standard input so it never appears on a command line:

   ```sh
   npm install -g github:bnap00/cf-ephemeral-share   # or: npm link, in a clone
   ef config set host https://files.example.com
   ef config set token - < token.txt
   ef recipient add me efpk1.…                        # the line /keys shows
   ```

   This writes `~/.config/ef/config.json` (or `$EF_CONFIG`), owner-only.
3. The agent sends with `ef send`:

   ```sh
   ef send ./credentials.json                       # a file
   some-command | ef send - --name db.env           # stdin
   ef send --from-env DATABASE_URL                  # an environment variable
   ef send --generate 32 --name new-api-secret      # a fresh random secret
   ef send ./report.pdf --to me --limit 3 --ttl 3600 --json
   ```

   It prints the link (or, with `--json`, the link, ID, expiry, read limit,
   recipients and delete token) and nothing derived from the content.
4. The recipient opens the link in the browser holding the key. The page
   unseals the link key locally and continues exactly like any other share.
   Any other browser is told the link is sealed to a key it does not have,
   and requests nothing from the server.

`ef send` differs from `ef put` in its defaults, to suit an unattended
sender:

- It refuses to run without a receiving key, unless given `--unsealed`, which
  prints a plain link and a warning.
- One read and one day, unless `--limit` or `--ttl` say otherwise.
- It refuses `--text` and `--password`, which would put a secret on the
  command line, and directories.
- It refuses plain `http` to anything but this machine.

`ef put --to <recipient>` seals an ordinary upload the same way. Recipients
are names from `ef recipient list` or literal `efpk1.…` keys; `--to` can be
given up to eight times, and any one of the keys opens the link. Manage them
with `ef recipient add|rm|list` and `ef config set default <name>`.

A person who would rather receive in a terminal can run `ef keygen --label
laptop`, which stores a private key under `~/.config/ef/keys/` (owner-only) and
prints its public half. `ef get` then opens links sealed to it. Anything that
can read that directory, including an agent running as the same user, can
open those links, so prefer the browser for agent-to-human sharing.

What sealing protects, and what it does not:

- The link is not a secret. A transcript, log or chat message that contains
  it cannot decrypt the share. On a deployment with
  `DOWNLOAD_AUTH = "enforce"` it cannot spend the read either, because the
  download key is derived from the sealed link key. Without enforcement,
  someone with the share ID can still burn a one-read link without reading
  it, so enforce download keys if agents send to you.
- The sender still has the content: it produced it. The
  [`ephemeral-send` skill](skills/ephemeral-send/SKILL.md) instructs agents to
  pipe files and secrets straight into `ef send` without displaying them,
  which keeps them out of the agent's context and transcript. That is a
  convention the agent follows, not something the CLI can enforce.
- The upload token is a capability: whatever holds it can create shares.
  Give an agent its own deployment, or rotate the token when you stop using
  the agent.
- The receiving key is tied to one browser profile. Clearing the site's data
  deletes it, and links sealed only to it can never be opened.

The sealed fragment is `r1.<ephemeral public key>.<kid>.<wrapped>`, repeated
`<kid>.<wrapped>` per extra recipient:

```text
shared   ECDH-P256(ephemeral private, recipient public)
kek      HKDF-SHA256(shared, salt = epk || recipient public,
                     info "ephemeral-files/v1/recipient")
wrapped  AES-256-GCM(kek, iv = 0^12, aad = "r1" || kid, link key)
kid      SHA-256(recipient public)[0..8]
```

Each share uses a fresh ephemeral key, so every key-encryption key is used
once. The Worker sees none of this; sealed shares need no server change.

#### The agent skill

`skills/ephemeral-send/` is an agent skill (Claude Code and compatible
agents) that teaches an agent to check the setup, send with `ef send`, never
read, print or type the content, and report only the link. Install it by
copying or linking the directory into the agent's skills folder:

```sh
ln -s "$PWD/skills/ephemeral-send" ~/.claude/skills/ephemeral-send
```

Its `scripts/ef.sh` runs `$EF_CLI` (a path to `tools/ef.mjs`) if set, or `ef`
on `PATH`.

### Download API

Other clients can use the same endpoints. Every field and header below is
optional, and Workers that predate them ignore them.

- `POST /api/upload/complete` accepts `auth`, the download verifier: the
  base64url SHA-256 of the download key, 43 characters without padding. Any
  other shape gets a 400 response.
- `GET /api/f/<id>` returns `auth: true` when the share has a verifier.
- `GET /api/config` returns `downloadAuth`, either `"enforce"` or `"optional"`.
- `GET` and `HEAD /api/d/<id>` accept `x-ef-auth`, the base64url download key
  (43 characters). For a share with a verifier, a wrong or malformed key gets
  a 403 response. A missing key gets a 401 response when the deployment
  enforces keys. Neither spends a download. Shares without a verifier ignore
  the header.
- `GET /api/d/<id>` serves a single `Range: bytes=N-` or `bytes=N-M` with a 206
  response and `content-range`. An end past the file is clamped to the last
  byte. Suffix ranges, multiple ranges, other units, and a start past the end
  get a 416 response and spend nothing. Every 200, 206 and `HEAD` response
  carries `accept-ranges: bytes`. `HEAD` ignores `Range`.
- A counted download carries `x-resume-ticket`, an opaque value, when the
  deployment has an `UPLOAD_TOKEN`. Sending it back with a `Range` request
  for the same ID continues the download without loading or counting the
  share. That response carries a fresh ticket and no `x-downloads-remaining`.
  A 404 there means the object is gone and the download cannot be resumed.
  Renew a ticket by requesting the one byte where a resume would start: a
  chain whose requests do not move at least one chunk forward ends after
  eight of them.
- A `Range` request that carries a ticket the Worker cannot use, for a share
  with a download limit, gets a 410 response and spends nothing. Start the
  download again without the ticket. A ticket that has expired, was issued
  before `UPLOAD_TOKEN` or `TICKET_SECRET` changed, was issued to a request
  without a key before the deployment started enforcing keys, or has used up
  its renewals is not usable. For an unlimited share the range is served
  anyway. Stop using a ticket before ten minutes have passed.
- A `Range` request without a ticket counts as a new download.

To resume, request the ciphertext from a chunk boundary: chunk number times
the chunk size plus 16 bytes, using the chunk size from the decrypted header.

## Configuration

| Setting | Location | Default |
| --- | --- | --- |
| Per-file size cap | `MAX_SIZE_MB` in `wrangler.toml` | 5120 MiB |
| Expired-object sweep | `crons` in `wrangler.toml` | Hourly |
| Per-IP rate limits | `[[ratelimits]]` in `wrangler.toml` | Disabled |
| Worker logs | `[observability]` in `wrangler.toml` | Enabled |
| Upload access | Wrangler secret `UPLOAD_TOKEN` | Uploads disabled |
| Resume ticket secret | Wrangler secret `TICKET_SECRET` | Random, kept in KV |
| Download keys | `DOWNLOAD_AUTH` in `wrangler.toml` | Optional |
| Exact download counts | `COUNTER` Durable Object binding in `wrangler.toml` | Disabled, counts in KV |
| Brand name | `BRAND_NAME` in `wrangler.toml` | `ephemeral` |
| Tagline | `BRAND_TAGLINE` in `wrangler.toml` | Built-in encryption tagline |
| Footer | `BRAND_FOOTER` in `wrangler.toml` | Built-in encryption note |
| Logo | `BRAND_LOGO` in `wrangler.toml` | None |
| Accent colors | `BRAND_ACCENT`, `BRAND_ACCENT_DARK` in `wrangler.toml` | Blue |

The UI offers expiry periods from 10 minutes to 30 days and download limits
from one read to unlimited. The Worker enforces both.

The Worker rejects a download limit that is not a number, and truncates a
fractional one (`1.5` becomes 1). An absent limit means unlimited. A negative
limit also means unlimited, as it always has, because older CLI copies send
`--limit -1` unchecked; the Worker logs a warning when it sees one. The
current CLI and the browser never send one.

Files of more than one chunk need a chunk size of at least 5 MiB minus 16
bytes, because R2 multipart parts other than the last must be at least 5 MiB.
The browser and CLI use 8 MiB.

The optional rate-limit examples in `wrangler.toml` need namespace IDs unique
to your Cloudflare account. Uncomment them only after choosing those IDs.
`UPLOAD_LIMIT` counts upload starts and token checks. A bundle of N files
starts N + 1 uploads, so leave room for your largest bundle. `DOWNLOAD_LIMIT`
counts downloads, and it counts share lookups on a separate counter. Revokes
are not throttled, since each one needs the share's delete token. The browser
retries with backoff after a 429 response.

With `[observability]` enabled, the Worker logs errors and sweep results as
JSON lines. Error lines include the route, with share IDs replaced by `:id`,
and the `cf-ray` ID, which a 500 response also returns. Invocation logs are
turned off in `wrangler.toml` (`invocation_logs = false`), because Cloudflare
would otherwise retain one record per request with its full URL, share ID
included. Turning them on means request URLs, and so share IDs, are kept for
the Workers Logs retention period. A missing `META`,
`BUCKET`, or `ASSETS` binding returns a 503 response that names the binding.
An invalid `MAX_SIZE_MB` falls back to 5120 and logs a warning.

Resume tickets, described under
[Large and interrupted downloads](#large-and-interrupted-downloads), are signed
with a random 32-byte secret that the Worker creates on first use and keeps in
KV under `k:ticket-secret`, combined with `UPLOAD_TOKEN`. The token alone is
not enough to sign or check a ticket, so a ticket gives its holder no way to
guess the token offline. To manage the secret yourself instead, set a
`TICKET_SECRET` Wrangler secret to a long random value (`npm run token`).
Rotating `UPLOAD_TOKEN` or `TICKET_SECRET` invalidates every ticket in use; a
download in progress then cannot resume and has to start again, which spends a
view of a limited share. When two locations create the KV secret at the same
moment right after a deployment, a few tickets may fail to verify for a minute
or so in the same way.

### Key-bound downloads

Shares uploaded by current browsers and by `ef put` store a download verifier.
The client derives a 32-byte download key from the link key with HKDF-SHA-256
and registers only its SHA-256 hash. The download key is a separate HKDF
output, so it reveals nothing about the encryption key. It ignores the
password and salt, so the Worker can check it without them. The browser sends
the download key in an `x-ef-auth` header with every download, and the Worker
compares hashes in constant time.

This stops someone who knows a share ID but not its link key, for example from
a log, a proxy, or a URL copied without its fragment, from spending a one-read
link or fetching its ciphertext. A wrong key gets a 403 response and spends
nothing. The share's metadata at `/api/f/<id>` stays readable with the ID
alone: the encrypted header, size, expiry and remaining count.

`DOWNLOAD_AUTH` decides what happens to a download that sends no key:

- Unset, the default: the download is allowed and counted as before. App
  pages cached before the change, installed PWAs that have not reloaded since,
  and command-line clients keep working. In this mode the check only stops
  wrong keys. Anyone with the ID alone can still download by leaving the
  header out.
- `"enforce"`: the download gets a 401 response and spends nothing. Any other
  value counts as unset.

Shares uploaded by older clients, or before this change, have no verifier and
are never challenged under either setting.

To turn enforcement on, deploy this version first and wait a few days. The
service worker fetches the app files network-first, so an open tab or an
installed PWA picks up the new page the next time it loads online. Then
uncomment `DOWNLOAD_AUTH = "enforce"` in `wrangler.toml` and deploy again.
Before you do, check how your recipients download: copies of `ef get` older
than this change do not send the download key, so enforcement locks them out
of every share that has a verifier.

### Exact download counts

By default, download counts and burns are stored in KV, which is eventually
consistent (see [Known limits](#known-limits)). The optional `DownloadCounter`
Durable Object makes limits exact. Each limited share gets one object, named
after its ID, which claims downloads one at a time before the Worker reads
from R2. A one-read link then serves at most one counted download, wherever
the requests come from.

To turn it on, uncomment the `[[durable_objects.bindings]]` and
`[[migrations]]` blocks in `wrangler.toml` and deploy. The migration creates
the SQLite-backed class. Keep the migration block if you remove the binding
later, because deleting the class needs a `deleted_classes` migration.

Links created before you turn it on keep their remaining downloads. Each
claim takes the higher of the object's own count and the count stored in KV,
so downloads counted in KV while the binding was removed still count when you
add it back. The Worker still writes each new count and burn to KV, so share
pages show the remaining count and the deployment can go back to KV if you
remove the binding. Unlimited shares and `HEAD` requests never use the
counter. Each object deletes its storage an hour after its share expires, and
revoking a share clears it.

The Worker opens the R2 object before it claims a download, so a failed R2
read spends nothing. If the counter fails, a download of a limited share gets
a 500 response instead of going uncounted, and nothing is spent. If the KV
burn fails after the counter has claimed a download, the download is served
anyway, because the counter already refuses any more; the error is logged and
the object is removed at the share's expiry instead of by the next sweep.

Each download of a limited share costs one Durable Object request, and
revoking a limited share costs another. Each object stores one number until
its share expires. SQLite-backed Durable Objects are available on the Workers
Free plan. Check Cloudflare's pricing for your plan's limits.

### Branding

Uncomment the `BRAND_*` values in `wrangler.toml` and deploy again. The name,
tagline, footer, logo, and light/dark accent colors apply to both the upload page
and shared links. Set `BRAND_TAGLINE` or `BRAND_FOOTER` to an empty string to
hide it.

`BRAND_LOGO` must point to a file committed under `public/`, for example
`/acme-logo.svg`. External logo URLs are rejected so the existing content
security policy stays strict. Color an SVG logo with attributes such as
`fill="#0d9488"`, not a `<style>` block: the policy sets `style-src 'self'`,
and browsers that apply it to images drop the block and draw the logo
black. Accent colors must use six-digit hex notation.
The interface picks black or white button text based on each accent color.

The browser tab title changes at runtime. To brand the installed PWA too, edit
`public/manifest.webmanifest`, replace the icon files under `public/icons/`, and
update `public/favicon.svg`.

## How encryption works

The browser splits plaintext into 8 MiB chunks and seals each chunk separately.
Uploads use R2 multipart upload with one part per encrypted chunk.

```text
key      HKDF-SHA256(link key + PBKDF2-SHA256(password, 600k), salt)
header   salt + nonce base + GCM(filename, type, size, chunk count,
                                 chunk size, padding)               -> KV
body     GCM(chunk 0) + GCM(chunk 1) + ...                         -> R2
nonce    nonce base + u32be(chunk index)
aad      u32be(chunk index) + final-chunk flag
dl key   HKDF-SHA256(link key, no salt, "ephemeral-files/v1/auth")  -> x-ef-auth
verifier SHA-256(download key)                                      -> KV
```

The chunk index and final-chunk flag are authenticated data. Reordering,
dropping, duplicating, or moving chunks between files causes authentication to
fail. The encrypted header records the expected chunk count, which catches
truncation. Headers written before the chunk size was recorded open as 8 MiB
chunks, so older links keep working.

The Worker compares upload tokens in constant time. It bounds multipart part
sizes and counts against the declared file size. When an upload completes, it
checks the part list and compares the stored size with the declared size.
Downloads use
`application/octet-stream`, attachment disposition, and a sandboxed content
security policy, so uploaded content is not served as HTML or script. Unknown
paths return 404 instead of the application shell.

When a download uses up a share's last read, the Worker deletes the KV record
and writes a tombstone before sending the first byte. Without the download
counter, if either write fails, the request fails and the bytes are not
served. The R2 object stays in place
for the sweep to collect, so cleanup never deletes bytes during an active
response. Earlier downloads of a limited share update the count in the
background. With the optional download counter, the Durable Object claims the
download first and KV gets the same updates afterwards. Unlimited shares are
not counted at all. A `HEAD` request never spends a read. A refused download
key and an unsatisfiable range are rejected before anything is counted.

## Operational notes

The hourly cron in `wrangler.toml` runs the sweep. Without it, expired and
burned objects stay in R2 and abandoned uploads are never aborted. Each run
has three steps, and a failure in one does not stop the others:

- Deletes R2 objects whose expiry has passed.
- Deletes the objects of burned links. It skips tombstones younger than ten
  minutes, so a download in progress can finish or resume. It handles up to
  500 per run.
- Aborts multipart uploads that were not completed within six hours of their
  start. It handles up to 200 per run.

A backlog larger than these caps is cleared over later runs. If any step
fails, the run is reported as failed in the Cloudflare dashboard. To try the
sweep locally, run `npm run sweep` and request `/__scheduled` on the local
Worker.

KV entries also expire without the sweep: tombstones after 35 days, pending
uploads after 8 days. The 8-day expiry assumes the R2 bucket keeps its default
rule for aborting incomplete multipart uploads.

A share's expiry is counted from the start of its upload, not from its
completion. An upload that completes after its expiry is aborted and gets a 410
response.

## Local development and tests

Create `.dev.vars` with a local token before starting Wrangler:

```dotenv
UPLOAD_TOKEN=test-token-do-not-use-in-production
```

Run the local Worker:

```sh
npm run dev
```

The unit tests need only Node 22 or later, with no installed packages and no
running Worker. They cover the crypto format, including fixed test vectors from
older versions, download keys and resume offsets, and the branding config.
They also run the Worker against in-memory fakes of KV, R2, the asset server
and the download counter, and the command-line client against that Worker:

```sh
npm test
```

The browser test needs Playwright and expects the local Worker at
`http://127.0.0.1:8787` and the test token shown above:

```sh
npm run test:ui
```

Set `CHROMIUM=/path/to/chrome` to use an existing Chromium installation.

### Secret scanning before commits

The repository ships a [pre-commit](https://pre-commit.com/) hook that runs
[Gitleaks](https://github.com/gitleaks/gitleaks) on staged changes. Install it
once per clone:

```sh
pre-commit install
```

CI runs Gitleaks, OSV-Scanner, CodeQL, and Semgrep on every pull request and
weekly. See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Known limits

- Without the optional [download counter](#exact-download-counts), download
  limits are a guardrail, not a lock. Counts and burns are stored in KV, which
  can take up to a minute or more to reach other Cloudflare locations. Within
  that window, requests served elsewhere can still read the old record. A
  one-read link fetched from two places at once may be downloaded twice, and a
  limited link may go past its limit. With the counter, limits are exact, but
  the remaining count shown on share pages still comes from KV and can lag.
- Without the counter, a count written in the background can rarely bring back
  a record that was revoked or burned at the same moment. With it, such a
  record still refuses downloads past its limit.
- A resume ticket is a bearer value: whoever holds it can read the same
  ciphertext again, in full or in part, without spending a view, and can pass
  it on. Each ticket can be replayed until it expires, about ten minutes. A
  chain of renewed tickets lasts at most six hours, never more than ten
  minutes past the share's expiry, and only while the object exists; one that
  keeps re-reading without moving forward through the file ends after eight
  renewals. The ciphertext is useless without the link key, and in
  non-enforcing mode a share ID alone can already download.
- Until `DOWNLOAD_AUTH` is set to `"enforce"`, download keys stop only wrong
  keys. A share ID alone can still download a share by leaving the key out.
- Copies of the command-line client older than download keys cannot open
  shares with a verifier on a deployment that enforces them.
- Browsers with neither a save picker nor streaming writes to OPFS, such as
  older Safari releases, assemble the decrypted file in memory before saving
  it. On the OPFS path, the browser keeps a second, decrypted copy of the
  file in its own storage until ten minutes after the hand-off. If the tab
  is closed or crashes before then, the copy stays until a page of the same
  deployment loads again in that browser, which removes it if it is old
  enough (see [Large and interrupted downloads](#large-and-interrupted-downloads)).
- The Worker holds one encrypted chunk in memory for each active multipart part.

## Self Promotion

*Put together with ❤️ by [Bharat Parsiya](https://bnap.dev/)*


## License

[MIT](LICENSE)
