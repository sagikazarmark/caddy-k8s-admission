[private]
default:
  @just --list

check:
    dagger call check

test:
    dagger call test

lint:
    dagger call lint

fmt:
    golangci-lint fmt

release bump='minor':
    #!/usr/bin/env bash
    set -euo pipefail

    git checkout main > /dev/null 2>&1
    git diff-index --quiet HEAD || (echo "Git directory is dirty" && exit 1)

    version=v$(semver bump {{bump}} $(git tag --sort=v:refname | tail -1 || echo "v0.0.0"))

    echo "Tagging repo with version ${version}"
    read -n 1 -p "Proceed (y/N)? " answer
    echo

    case ${answer:0:1} in
        y|Y )
        ;;
        * )
            echo "Aborting"
            exit 1
        ;;
    esac

    tag=$version

    git tag -m "Release ${version#v}" $tag
    git push origin $tag
