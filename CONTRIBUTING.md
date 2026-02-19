# Contributing

Thanks for contributing to Smith Core.

## Prerequisites

- Rust stable toolchain
- Node.js 22+
- Docker + Docker Compose

## Development Setup

```bash
just up
just npm-install
just build-all
```

## Validation

Run these before opening a pull request:

```bash
cargo check --workspace
# agentd lives in a separate repo (set AGENTD_ROOT in .env):
cargo check --manifest-path ${AGENTD_ROOT}/Cargo.toml
npm run build --workspaces --if-present
cd installer && npm test
```

## Pull Request Guidelines

- Keep PRs focused and small when possible.
- Include tests for behavior changes.
- Update docs (`README.md`, service docs, `.env.example`) when config or runtime behavior changes.
- Use clear commit messages describing what changed and why.

## Reporting Issues

Use GitHub Issues for bug reports and feature requests. Include repro steps, expected behavior, and actual behavior.
