# Manual Release Procedure

This checklist is for the ConfigGuard maintainer. Releases are manual; CI does not publish
packages or create GitHub releases.

## Prepare and verify

1. Work on the rewritten `main` branch and confirm the working tree is clean.
2. Confirm the repository-local Git identity uses the approved public GitHub noreply address.
3. Confirm `configguard version` and package metadata report the intended release version.
4. Run the complete local checks:

   ```text
   python -m pytest
   python -m ruff check src tests
   python -m ruff format --check src tests
   python -m mypy
   python -m build
   git diff --check
   ```

5. Install the newly built wheel in a clean temporary environment and verify the CLI, JSON,
   HTML, and local Web UI health/frontend routes.
6. Inspect wheel and sdist contents and generate checksums for the final artifacts.

## Publish manually

Only after the public GitHub repository has been created and reviewed:

1. Configure the maintainer-approved repository URL as `origin`.
2. Push only the rewritten primary branch:

   ```text
   git push -u origin main
   ```

3. Create the annotated release tag locally:

   ```text
   git tag -a v0.1.0 -m "ConfigGuard v0.1.0"
   ```

4. Push only that tag:

   ```text
   git push origin v0.1.0
   ```

5. Create GitHub Release `v0.1.0`, use the matching changelog entry as release notes, and
   attach both `configguard-0.1.0-py3-none-any.whl` and `configguard-0.1.0.tar.gz` with their
   checksums.
6. Verify the release page, download both artifacts, and repeat the clean-wheel smoke test.
7. Enable GitHub Private Vulnerability Reporting in the repository Security settings.

## Critical history-safety boundary

The local branch `backup/pre-noreply-history` exists only as a temporary recovery reference
and contains private historical author metadata. Never publish it.

Do not use:

```text
git push --all
git push --mirror
```

Delete the local backup branch only after the public `main` branch and release have been
independently verified.
