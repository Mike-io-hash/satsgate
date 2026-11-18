# Publishing satsgate

This is the runbook for publishing the four Python packages and the proxy image.
Nothing in this repository publishes by itself. Ia approves each upload in GitHub,
and she also says so in chat before that upload. Nobody pastes a password, a recovery
code, or a token into chat or into the repo.

The workflow file is `publish.yml`. The image workflow is `ghcr.yml`. The GitHub
environments are `testpypi`, `pypi`, and `ghcr`. Those names are what PyPI and the
workflows match. A rename breaks the first upload.

## 1. GitHub account

**Who:** Ia, in a browser.

The GitHub account that owns or administers `Mike-io-hash/satsgate` has 2FA on.

## 2. PyPI account

**Who:** Ia, in a browser.

Register at `https://pypi.org/account/register/` with the email `satsgateapp@proton.me`
and a password. Do not use a "sign in with" button. The username is `satsgate`. If PyPI
says that name is taken, use `satsgateapp` and tell Mike which one is public. Verify the
email, turn on 2FA (a TOTP app and, if you have one, a security key), and store the
recovery codes offline. PyPI requires 2FA to publish.

## 3. TestPyPI account

**Who:** Ia, in a browser.

Register at `https://test.pypi.org/account/register/`. This is a separate account and a
separate database. Use the same email and the same username, with its own 2FA and its
own recovery codes.

## 4. Pending publishers

**Who:** Ia, in a browser.

On PyPI (`https://pypi.org/manage/account/publishing/`) add four pending publishers:

| PyPI project name | Owner | Repository | Workflow | Environment |
| --- | --- | --- | --- | --- |
| `satsgate-sdk` | `Mike-io-hash` | `satsgate` | `publish.yml` | `pypi` |
| `satsgate-proxy` | `Mike-io-hash` | `satsgate` | `publish.yml` | `pypi` |
| `satsgate-mcp` | `Mike-io-hash` | `satsgate` | `publish.yml` | `pypi` |
| `satsgate` | `Mike-io-hash` | `satsgate` | `publish.yml` | `pypi` |

On TestPyPI (`https://test.pypi.org/manage/account/publishing/`) add the same four, with
Environment `testpypi`. A pending publisher does not reserve the name.

## 5. GitHub environments

**Who:** Ia, in a browser. Repo → Settings → Environments.

Create `testpypi`, `pypi`, and `ghcr`. For each one:

- Required reviewers: Ia. `pypi` is required by the publishing recommendation. `testpypi`
  and `ghcr` also wait for her approval.
- Do not enable "Prevent self-review". Ia is the only reviewer and may also be the
  person who created the tag.
- Deployment branches and tags: Selected tags, patterns `sdk-v*`, `proxy-v*`, `mcp-v*`,
  and `satsgate-v*`. For `ghcr`, the only pattern is `proxy-v*`.
- No environment secrets.

## 6. Tag ruleset

**Who:** Ia, in a browser. Repo → Settings → Rules → Rulesets → New tag ruleset.

Target `*-v*`. Restrict creation, update, and deletion to repository admins. Block force
pushes. A released tag is never moved or reused. The old tag `v0.2.0` does not match
`*-v*` and is not touched.

## 7. Releasing one package

**Who:** Ia creates the tag, after her OK in chat for that package and version. The
workflow does the build. Mike does not push tags.

1. GitHub → the repo → Releases → "Draft a new release" → "Choose a tag". Type the exact
   tag Mike gives (for example `sdk-v0.10.0`) and pick "Create new tag on publish".
   Target: `main`. Title: the tag. Notes: the text Mike gives. Leave "Set as a
   pre-release" off. Click **Publish release**. A saved draft does not create the tag
   and triggers nothing. A tag created this way fires `on: push: tags`, the same as
   `git push`. GitHub documents that under "Events that trigger workflows → push":
   https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#push
2. Within 2 minutes a `publish` run for that tag appears under Actions. The workflow
   builds, checks, and smoke-tests locally. On the first release of that project it
   stops at `testpypi`. Ia approves that rehearsal, with her chat OK for the rehearsal.
   The workflow publishes to TestPyPI, downloads the files back, and compares hashes.
   It then stops at `pypi`. Ia approves that, with her chat OK for PyPI. Later versions
   of a project that already exists skip the TestPyPI stop. If a check fails, nothing
   goes to PyPI. A version uploaded to TestPyPI or PyPI cannot be uploaded again, so
   the fix is a new patch version.
3. **Plan B, if no run appeared within 5 minutes.** Nothing was uploaded. Uploads only
   happen inside a run, after Ia's approval. Mike checks, read-only, the public Actions
   page and that `publish.yml` is on `main` with the tag pattern, and reports the cause.
   Then, because the tag never triggered anything: Ia deletes that release and its tag
   (Releases → the release → Delete; Tags → the tag → Delete). After the cause is fixed
   (a workflow fix is a normal pull request that Ia merges), she creates the tag again
   from Releases, the same way as above. If the Releases page itself is the cause, Ia
   runs this on her own computer, in a clone of the repo, with the exact line Mike gives:
   `git fetch origin && git tag -a <tag> -m "<tag>" <merged-main-sha> && git push origin <tag>`.
   Mike never pushes tags. A tag that did trigger a run is never deleted or reused.

## 8. First release order

**Who:** Ia, one package at a time, each with its own chat OK.

`sdk` → `proxy` (PyPI) → the proxy image (`ghcr.yml`, from the same `proxy-v*` tag) →
`mcp` → `satsgate`. `satsgate` depends on the SDK and the proxy, and `init --docker`
names the GHCR image, so the image has to exist before `satsgate` is on PyPI.
On a `proxy-v*` tag, `ghcr.yml` starts beside `publish.yml`. Approve the `ghcr` environment only after `verify-pypi` is green.

The versions for that first train are `sdk-v0.10.0`, `proxy-v0.14.1`, `mcp-v0.13.0`,
and `satsgate-v0.1.1`.

## 9. GHCR, first time only

**Who:** Ia, in a browser, after the first `proxy-v*` image run.

GitHub → Packages → `satsgate-proxy` → Package settings. Check that it is linked to the
repo, set visibility to **Public** (it starts private), and leave "Inherit access" on.
Then `docker pull ghcr.io/mike-io-hash/satsgate-proxy:<version>` works without logging in.
The image tags are `X.Y.Z`, `X.Y`, and `latest` only when that version is the newest
stable proxy tag.

## 10. After each release

**Who:** Mike, read-only, then the bitácora.

Check that the PyPI page renders, the attestation shows "Trusted Publisher", and
`pip install <name>==<version>` works in a clean virtualenv. Record the version, the
run URL, and the file hashes. Do not record a token.

## 11. If something goes wrong

**Who:** Ia yanks. Mike does not delete a release that already uploaded.

A bad release is yanked on PyPI (project → Releases → Yank), not deleted, and fixed
with a new patch. A bad image tag is replaced by a new patch tag. Never move `X.Y.Z`.
If a publisher was misconfigured, the job fails with an OIDC error and nothing is
uploaded. Fix the publisher fields so the filename and the environment match exactly,
then re-run the failed job.
