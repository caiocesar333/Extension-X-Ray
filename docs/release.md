# Release checklist

Use this checklist for every Extension X-Ray release. A release is complete only after the commands and manual observations are recorded truthfully in `PROGRESS.md`.

## Prepare

1. Choose the version from the compatibility rules and update `CHANGELOG.md`.
2. Synchronize `backend/app/__init__.py`, `backend/pyproject.toml`, `frontend/package.json`, and both root version fields in `frontend/package-lock.json`.
3. Update version-specific README, security, CI, and progress text.
4. If a document shape changed, assign and document its schema version, update backend and frontend types together, and add compatibility tests.

## Verify

From the repository root on PowerShell:

```powershell
.\.venv\Scripts\python -m pip install -e ".\backend[dev]"
.\.venv\Scripts\extension-xray --version
.\.venv\Scripts\python -m pip check
.\.venv\Scripts\python -m pytest backend
Set-Location frontend
npm ci
npm audit
npm run typecheck
npm run lint
npm run test -- --run
npm run build
Set-Location ..
```

Regenerate all four synthetic artifacts and analyze the benign and suspicious VSIX and repository fixtures. Validate every JSON report through its Pydantic model, run the suspicious repository CI-policy and baseline smoke tests, confirm sensitive fixture material is redacted, and exercise health plus both upload routes manually.

Review the diff for generated files, secrets, real wallet material, unsafe target execution, dependency drift, mutable Action references, and unintentional report-contract changes.

## Commit and tag

1. Commit the verified release as one auditable release change.
2. Create an annotated immutable tag named `vX.Y.Z` on that commit.
3. Verify `git status`, the tag target, and the version printed by the installed CLI.
4. Push the commit and tag only after review. Publishing is an explicit maintainer action; the repository does not publish packages merely because a tag exists.

Never move an existing release tag. Correct a released version with a new patch, minor, or major version as required by the compatibility contract.
