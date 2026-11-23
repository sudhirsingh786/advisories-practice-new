# InfoSec security advisories

Static, read-only advisory pages for company-wide vulnerabilities (CVEs). InfoSec or product line
engineers write one Word (.docx) file per CVE; a GitHub Actions workflow turns them into HTML and
publishes them to GitHub Pages. Tracking (Identify, Prioritize, Remediate, Monitor) stays in
Confluence and ServiceNow.

## Layout

Everything for the advisory site lives in this folder, so the rest of the repo is untouched.

| Path | What it is |
|---|---|
| `infosec-advisory/advisories/CVE-*.docx` (or `.md`) | One advisory per CVE; the file name is the CVE ID |
| `infosec-advisory/templates/advisory-template.docx` | Word template (recommended) |
| `infosec-advisory/templates/advisory-template.md` | Markdown template (optional) |
| `infosec-advisory/tools/build.py` | Builder, Python standard library only |
| `infosec-advisory/site/assets/style.css` | Single local stylesheet |
| `infosec-advisory/site/priority.md` | Priority and SLA table on the front page (keep in line with ServiceNow) |
| `.github/workflows/publish-advisories.yml` | Build and deploy; must sit at the repo root |
| `.github/CODEOWNERS` | InfoSec approves changes to this folder |

## Publish a new advisory

1. Copy `templates/advisory-template.docx`, fill it in Word and save it as `CVE-YYYY-NNNNN.docx`.
2. Upload it to `infosec-advisory/advisories/` (pull request recommended).
3. When the commit reaches `main`, the workflow builds and publishes the site in about a minute.

To change an advisory, upload the edited file with the same name. To remove one, delete the file.

## What starts the workflow

- A commit on `main` that changes anything under `infosec-advisory/` or the workflow file
  (web upload, `git push`, or a merged pull request).
- Actions > Publish advisories > Run workflow (manual).

Commits to other folders or other branches do not start it.

## How the builder behaves

- No Word heading styles are required; headings, typed bullets, numbering and merged table cells are detected.
- The document order is kept; the last section "Vulnerability details" is published as written.
- Published = the header date if valid, else the file's first Git commit. Updated = the file's last Git commit.
- Stage must be one of Identify, Prioritize, Remediate, Monitor, Closed (default Identify).
- Anything it has to guess shows as a warning in the Actions run; a broken file gets a stub page
  and never stops the other advisories.

## Security settings

- Settings > Pages: Source = GitHub Actions. Private visibility needs GitHub Enterprise Cloud.
- On a free plan Pages needs a public repo, which makes every file in the repo public.
- Branch protection on `main`: pull request required, 1 CODEOWNERS approval, no force push.
- Every action in the workflow is pinned to a full commit SHA.
- Pages output has no JavaScript and a Content-Security-Policy that blocks scripts and outbound requests.
- Never put customer names, hostnames, IP addresses or exploit code in an advisory.
