# RELEASE

Release process and checklist for `certgen`.

## Modify the Version

Update the Version `var` in `internal/version/version.go`

    git add internal/version/version.go
    git commit -s -m "version: Prepare for $MAJOR.$MINOR.$PATCH release"

## Push the prep branch and open a Pull Request

Once the pull request is approved and merged, a tag can be created.

## Tag a release

Identify the right commit and tag the release.

Example:

    git tag -a v0.1.4 -m 'v0.1.4' <commit-sha>

Then push the tag.

Example:

    git push origin v0.1.4

Once tagged, the release will be built automatically and pushed to both quay.io
and docker.io via GitHub actions.
