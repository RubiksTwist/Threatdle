# Threatdle Public Repo Checklist

Use this checklist before making the repository public or posting the project on Reddit, LinkedIn, or a portfolio site.

## Secrets and access

- Remove API keys, tokens, `.env` files, private URLs, and deployment credentials.
- Check git history, not just the current working tree, for accidentally committed secrets.
- Rotate any credential that may already have been exposed during development.

## Data and redistribution

- Keep original project-authored materials public where useful, especially:
  - `data/curated-flows/`
  - `data/overrides/`
  - docs, tests, and synthetic fixtures
- Review whether each third-party source in the project can be redistributed in a public repository.
- Do not assume generated outputs are safe to publish just because they were produced locally.
- Be cautious with:
  - `data/processed/`
  - `data/snapshots/`
  - `dist/`
  - any exported static demo bundle
- If redistribution rights are unclear, keep code and small test fixtures public, and keep downloaded or generated datasets out of the public repo.

## Assets and branding

- Confirm that the logo and any non-code assets are original or safe to redistribute.
- Remove anything copied from a report, article, vendor site, or third-party design source without clear rights.

## Production posture

- Do not publish a production architecture that ships hidden answers to the client.
- Keep live answer validation server-side.
- Keep deployment-only configuration and environment-specific values out of the repo.

## Repo presentation

- Add a clear project overview in `README.md`.
- Include the live demo URL when available.
- Add a software license.
- Document the educational purpose, the stack, and the source-backed data model.

## Suggested minimum public shape

If you want the safest public version of Threatdle:

- publish source code
- publish docs
- publish curated flows and reviewed override files
- publish tests and synthetic fixtures
- avoid publishing full processed databases, downloaded source snapshots, and production demo bundles unless you have confirmed redistribution rights
