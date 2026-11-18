# Publishing satsgate

This is the runbook for publishing the four Python packages and the proxy image.
Nothing in this repository publishes by itself. The release approver approves each upload in GitHub,
and also says so in chat before that upload. Nobody pastes a password, a recovery
code, or a token into chat or into the repo.

The workflow file is `publish.yml`. The image workflow is `ghcr.yml`. The GitHub
environments are `testpypi`, `pypi`, and `ghcr`. Those names are what PyPI and the
workflows match. A rename breaks the first upload.

## 1. GitHub account

**Who:** the release approver, in a browser.

The GitHub account that owns or administers `Mike-io-hash/satsgate` has 2FA on.

## 2. PyPI account

**Who:** the release approver, in a browser.

Register at `https://pypi.org/account/register/` with the email `satsgateapp@proton.me`
and a password. Do not use a "sign in with" button. The username is `satsgate`. If PyPI
says that name is taken, use `satsgateapp` and record which one is public. Verify the
email, turn on 2FA (a TOTP app and, if you have one, a security key), and store the
recovery codes offline. PyPI requires 2FA to publish.

## 3. TestPyPI account

**Who:** the release approver, in a browser.

Register at `https://test.pypi.org/account/register/`. This is a separate account and a
separate database. Use the same email and the same username, with its own 2FA and its
own recovery codes.

## 4. Pending publishers

**Who:** the release approver, in a browser.

PyPI accepts one pending publisher per repository, workflow, and environment. Add them
one at a time. Add the next package's pending publisher only after the previous package
is published, and only just before its tag. Once a project exists, its publisher is
permanent and nothing is added for later versions.

On PyPI (`https://pypi.org/manage/account/publishing/`) the publisher fields are:

| PyPI project name | Owner | Repository | Workflow | Environment |
| --- | --- | --- | --- | --- |
| `satsgate-sdk` | `Mike-io-hash` | `satsgate` | `publish.yml` | `pypi` |
| `satsgate-proxy` | `Mike-io-hash` | `satsgate` | `publish.yml` | `pypi` |
| `satsgate-mcp` | `Mike-io-hash` | `satsgate` | `publish.yml` | `pypi` |
| `satsgate` | `Mike-io-hash` | `satsgate` | `publish.yml` | `pypi` |

On TestPyPI (`https://test.pypi.org/manage/account/publishing/`) use the same fields, with
Environment `testpypi`, still one project at a time. A pending publisher does not reserve the name.

## 5. GitHub environments

**Who:** the release approver, in a browser. Repo → Settings → Environments.

Create `testpypi`, `pypi`, and `ghcr`. For each one:

- Required reviewers: the release approver. `pypi` is required by the publishing recommendation. `testpypi`
  and `ghcr` also wait for that approval.
- Do not enable "Prevent self-review". The release approver is the only reviewer and may also be the
  person who created the tag.
- Deployment branches and tags: Selected tags, patterns `sdk-v*`, `proxy-v*`, `mcp-v*`,
  and `satsgate-v*`. For `ghcr`, the only pattern is `proxy-v*`.
- No environment secrets.

## 6. Tag ruleset

**Who:** the release approver, in a browser. Repo → Settings → Rules → Rulesets → New tag ruleset.

Target `*-v*`. Restrict creation, update, and deletion to repository admins. Block force
pushes. A released tag is never moved or reused. The old tag `v0.2.0` does not match
`*-v*` and is not touched.

## 7. Releasing one package

**Who:** the release approver creates the tag, after a chat OK for that package and version. The
workflow does the build. The maintainer does not push tags.

1. GitHub → the repo → Releases → "Draft a new release" → "Choose a tag". Type the exact
   tag (for example `sdk-v0.10.0`) and pick "Create new tag on publish".
   Target: `main`. Title: the tag. Notes are written by the maintainer. Leave "Set as a
   pre-release" off. Click **Publish release**. A saved draft does not create the tag
   and triggers nothing. A tag created this way fires `on: push: tags`, the same as
   `git push`. GitHub documents that under "Events that trigger workflows → push":
   https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#push
2. Within 2 minutes a `publish` run for that tag appears under Actions. The workflow
   builds, checks, and smoke-tests locally. On the first release of that project it
   stops at `testpypi`. The release approver approves that rehearsal, with a chat OK for the rehearsal.
   The workflow publishes to TestPyPI, downloads the files back, and compares hashes.
   It then stops at `pypi`. The release approver approves that, with a chat OK for PyPI. Later versions
   of a project that already exists skip the TestPyPI stop. If a check fails, nothing
   goes to PyPI. A version uploaded to TestPyPI or PyPI cannot be uploaded again, so
   the fix is a new patch version.
3. **Plan B, if no run appeared within 5 minutes.** Nothing was uploaded. Uploads only
   happen inside a run, after the release approver's approval. A reviewer (read-only checks) reads the public Actions
   page and that `publish.yml` is on `main` with the tag pattern, and reports the cause.
   Then, because the tag never triggered anything: the release approver deletes that release and its tag
   (Releases → the release → Delete; Tags → the tag → Delete). After the cause is fixed
   (a workflow fix is a normal pull request that the release approver merges), the release approver creates the tag again
   from Releases, the same way as above. If the Releases page itself is the cause, the release approver
   runs this on that person's own computer, in a clone of the repo:
   `git fetch origin && git tag -a <tag> -m "<tag>" <merged-main-sha> && git push origin <tag>`.
   The maintainer never pushes tags. A tag that did trigger a run is never deleted or reused.

## 8. First release order

**Who:** the release approver, one package at a time, each with its own chat OK.

`sdk` → `proxy` (PyPI) → the proxy image (`ghcr.yml`, from the same `proxy-v*` tag) →
`mcp` → `satsgate`. `satsgate` depends on the SDK and the proxy, and `init --docker`
names the GHCR image, so the image has to exist before `satsgate` is on PyPI.
On a `proxy-v*` tag, `ghcr.yml` starts beside `publish.yml`. Approve the `ghcr` environment only after `verify-pypi` is green.

The versions for that first train are `sdk-v0.10.0`, `proxy-v0.14.1`, `mcp-v0.13.0`,
and `satsgate-v0.1.1`.

## 9. Later versions

A later version of a project that already exists does not need a new pending publisher.
The release approver creates the tag from Releases. The workflow builds and runs checks.
The release approver approves `pypi`. There is no TestPyPI stop. After `verify-pypi` is green, check the
published files. Proxy tags also run `ghcr`. Approve the `ghcr` environment only after `verify-pypi` is green.
Release notes are written by the maintainer.

## 10. GHCR, first time only

**Who:** the release approver, in a browser, after the first `proxy-v*` image run.

GitHub → Packages → `satsgate-proxy` → Package settings. Check that it is linked to the
repo, set visibility to **Public** (it starts private), and leave "Inherit access" on.
Then `docker pull ghcr.io/mike-io-hash/satsgate-proxy:<version>` works without logging in.
The image tags are `X.Y.Z`, `X.Y`, and `latest` only when that version is the newest
stable proxy tag.

## 11. After each release

**Who:** a reviewer (read-only checks), then the release log.

Check that the PyPI page renders, the attestation shows "Trusted Publisher", and
`pip install <name>==<version>` works in a clean virtualenv. Record the version, the
run URL, and the file hashes in the release log. Do not record a token.

## 12. If something goes wrong

**Who:** the release approver yanks. The maintainer does not delete a release that already uploaded.

A bad release is yanked on PyPI (project → Releases → Yank), not deleted, and fixed
with a new patch. A bad image tag is replaced by a new patch tag. Never move `X.Y.Z`.
If a publisher was misconfigured, the job fails with an OIDC error and nothing is
uploaded. Fix the publisher fields so the filename and the environment match exactly,
then re-run the failed job.
