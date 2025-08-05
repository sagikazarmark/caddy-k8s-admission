package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sagikazarmark/caddy-k8s-admission/.dagger/internal/dagger"
)

// Release pre-built Caddy binaries to GitHub Releases.
func (m *CaddyKubeAdmission) Release(ctx context.Context, version string, githubToken *dagger.Secret) error {
	if githubToken == nil {
		return errors.New("GitHub token is required to publish a release")
	}

	err := dag.Gh(dagger.GhOpts{
		Token: githubToken,
		Repo:  "sagikazarmark/caddy-k8s-admission",
	}).Release().Create(ctx, version, version, dagger.GhReleaseCreateOpts{
		Files:         m.releaseAssets(),
		GenerateNotes: true,
		Latest:        dagger.GhLatestLatestTrue,
		VerifyTag:     true,
	})
	if err != nil {
		return err
	}

	_, err = dag.Container().
		WithRegistryAuth("ghcr.io", "sagikazarmark", githubToken).
		Publish(ctx, fmt.Sprintf("ghcr.io/sagikazarmark/caddy-k8s-admission:%s", version), dagger.ContainerPublishOpts{
			PlatformVariants: m.releaseContainers(),
		})
	if err != nil {
		return err
	}

	return nil
}

func (m *CaddyKubeAdmission) releaseAssets() []*dagger.File {
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
		binaries = append(binaries, m.Build("", platform).WithName(fmt.Sprintf("caddy_%s", strings.ReplaceAll(string(platform), "/", "_"))))
	}

	return binaries
}

func (m *CaddyKubeAdmission) releaseContainers() []*dagger.Container {
	platforms := []dagger.Platform{
		"linux/amd64",
		"linux/arm64",
	}

	containers := make([]*dagger.Container, 0, len(platforms))

	for _, platform := range platforms {
		containers = append(containers, m.Container("", platform))
	}

	return containers
}
