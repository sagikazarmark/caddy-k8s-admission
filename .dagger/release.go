package main

import (
	"context"
	"errors"

	"github.com/sagikazarmark/caddy-k8s-admission/.dagger/internal/dagger"
)

// Release pre-built Caddy binaries to GitHub Releases.
func (m *CaddyKubeAdmission) Release(ctx context.Context, version string, githubToken *dagger.Secret) error {
	if githubToken == nil {
		return errors.New("GitHub token is required to publish a release")
	}

	return dag.Gh(dagger.GhOpts{
		Token: githubToken,
		Repo:  "sagikazarmark/caddy-k8s-admission",
	}).Release().Create(ctx, version, version, dagger.GhReleaseCreateOpts{
		Files:         m.releaseAssets(version),
		GenerateNotes: true,
		Latest:        dagger.GhLatestLatestTrue,
		VerifyTag:     true,
	})
}

func (m *CaddyKubeAdmission) releaseAssets(version string) []*dagger.File {
	binaries := m.binaries()
	checksums := dag.Checksum().Sha256().Calculate(binaries)

	return append(binaries, checksums)
}

func (m *CaddyKubeAdmission) binaries() []*dagger.File {
	platforms := []dagger.Platform{
		"linux/amd64",
		"linux/arm64",

		"darwin/amd64",
		"darwin/arm64",
	}

	binaries := make([]*dagger.File, 0, len(platforms))

	for _, platform := range platforms {
		binaries = append(binaries, m.Build("", platform))
	}

	return binaries
}
