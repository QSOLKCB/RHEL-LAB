# No GitHub Pages — shutdown and prevention

## Observed problem

GitHub automatically published Pages from RHEL-LAB's main branch in
run 43184072056 on 2026-11-12, targeting commit
3209cbd9a2dc842c4f89f95336b1f66b15cc3391.
That run has completed successfully and cannot now be cancelled.

The repository has only .github/workflows/ci.yml. Pages uses GitHub's
server-managed dynamic workflow, not a committed deployment workflow.
A pull request alone cannot disable the Pages repository setting.

## Required administrator action

1. Open QSOLKCB/RHEL-LAB > Settings > Pages.
2. Under Build and deployment, change Source to Deploy from a branch
   (even if GitHub Actions is currently selected).
3. Select branch None, then Save.
4. Verify repository metadata has_pages is false and no new Pages run
   occurs on subsequent main pushes.

This removes the Pages site without deleting the repository or history.
Unpublishing a site alone can allow a later deployment to republish it.

Official GitHub instructions:
https://docs.github.com/en/pages/getting-started-with-github-pages/deleting-a-github-pages-site

## Source-controlled guard

The Pages-disabled job reads the repository metadata from GITHUB_EVENT_PATH
and fails unless has_pages is exactly false for QSOLKCB/RHEL-LAB.
It also rejects known publishing workflow patterns committed to this repo.

This job uses Python's standard library only; it performs no extra network
requests, site mutation, or deployment. Its unit tests use simulated events.

The guard is expected to FAIL while the repository's Pages site is enabled.
It cannot stop a deployment already running or alter GitHub administration
settings. The GitHub event is a snapshot; an administrator can still enable
Pages later. Review the repository configuration as a separate security gate.

No repository security policy should claim the site is disabled until GitHub
reports that it really is disabled.
