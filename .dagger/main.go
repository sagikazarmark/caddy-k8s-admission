package main

import (
	"context"

	"github.com/sagikazarmark/dagx/pipeline"

	"github.com/sagikazarmark/caddy-k8s-admission/.dagger/internal/dagger"
)

type CaddyKubeAdmission struct {
	// Project source directory
	//
	// +private
	Source *dagger.Directory
}

func New(
	// +defaultPath="/"
	// +ignore=[".devenv", ".direnv", ".github"]
	source *dagger.Directory,
) *CaddyKubeAdmission {
	return &CaddyKubeAdmission{
		Source: source,
	}
}

var supportedGoVersions = []string{"1.24"}

func (m *CaddyKubeAdmission) Check(ctx context.Context) error {
	p := pipeline.New(ctx)

	for _, goVersion := range supportedGoVersions {
		pipeline.AddSyncStep(p, m.Build(goVersion, ""))
	}

	pipeline.AddSyncStep(p, m.Test())
	pipeline.AddSyncStep(p, m.Lint())

	return pipeline.Run(p)
}

func (m *CaddyKubeAdmission) Build(
	// Go version to use.
	//
	// +optional
	goVersion string,

	// Target platform in "[os]/[platform]/[version]" format (e.g., "darwin/arm64/v7", "windows/amd64", "linux/arm64").
	//
	// +optional
	platform dagger.Platform,
) *dagger.File {
	var opts dagger.XcaddyBuildBinaryOpts

	if platform != "" {
		opts.Platform = platform
	}

	return m.build(goVersion).Binary(opts)
}

func (m *CaddyKubeAdmission) Container(
	// Go version to use.
	//
	// +optional
	goVersion string,

	// Target platform in "[os]/[platform]/[version]" format (e.g., "darwin/arm64/v7", "windows/amd64", "linux/arm64").
	//
	// +optional
	platform dagger.Platform,
) *dagger.Container {
	var opts dagger.XcaddyBuildContainerOpts

	if platform != "" {
		opts.Platform = platform
	}

	return m.build(goVersion).Container(opts)
}

func (m *CaddyKubeAdmission) build(goVersion string) *dagger.XcaddyBuild {
	if goVersion == "" {
		goVersion = defaultGoVersion
	}

	return dag.Xcaddy(dagger.XcaddyOpts{GoVersion: goVersion}).
		Build().
		Plugin("github.com/sagikazarmark/caddy-k8s-admission", dagger.XcaddyBuildPluginOpts{Replacement: m.Source})
}

func (m *CaddyKubeAdmission) Test() *dagger.Container {
	return dag.Go(dagger.GoOpts{
		Version: defaultGoVersion,
	}).
		WithSource(m.Source).
		Exec([]string{"go", "test", "-race", "-v", "./..."})
}

func (m *CaddyKubeAdmission) Lint() *dagger.Container {
	return dag.GolangciLint(dagger.GolangciLintOpts{
		Version:   golangciLintVersion,
		GoVersion: defaultGoVersion,
	}).
		Run(m.Source, dagger.GolangciLintRunOpts{Verbose: true})
}
