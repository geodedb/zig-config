# Contributing to zigconfig

Thank you for your interest in contributing to zigconfig!

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone git@gitlab.com:YOUR_USERNAME/zig/config.git
   ```
3. Set up the development environment (Zig 0.15.2+)
4. Run tests to verify setup:
   ```bash
   zig build test
   ```

## Development Workflow

### Building

```bash
# Build the library
zig build

# Check for compilation errors
zig build check
```

### Testing

```bash
# Run all tests
zig build test

# Run with test summary
make test
```

See: [#13 - Add integration tests with file fixtures](https://gitlab.com/devnw/zig/config/-/issues/13)

### Code Style

- Follow Zig standard library conventions
- Use doc comments (`///`) for public APIs
- Keep functions focused and small
- Prefer explicit error handling over panics

## Issue Tracking

All work is tracked in GitLab Issues. Before starting work:

1. Check existing issues for the feature/bug
2. Comment on the issue to claim it
3. Create a merge request linked to the issue

### Priority Labels

| Label | Description |
|-------|-------------|
| `priority::critical` | Security or blocking issues |
| `priority::high` | Important for next release |
| `priority::medium` | Should be addressed |
| `priority::low` | Nice to have |

### Type Labels

| Label | Description |
|-------|-------------|
| `type::feature` | New feature |
| `type::enhancement` | Improvement to existing feature |
| `type::bug` | Bug fix |
| `type::docs` | Documentation |
| `type::test` | Testing infrastructure |

### Component Labels

| Label | Description |
|-------|-------------|
| `component::parser` | YAML/JSON/TOML parsing |
| `component::loader` | Configuration loading |
| `component::xdg` | XDG Base Directory support |
| `component::secret` | Secret handling |
| `component::validation` | Validation utilities |

## Milestones

| Milestone | Focus |
|-----------|-------|
| [v0.1.0 - Foundation](https://gitlab.com/devnw/zig/config/-/milestones/1) | Core functionality, docs, tests |
| [v0.2.0 - Enhanced Loading](https://gitlab.com/devnw/zig/config/-/milestones/2) | Better loading, validation, errors |
| [v0.3.0 - Advanced Features](https://gitlab.com/devnw/zig/config/-/milestones/3) | Hot-reload, async, cross-platform |
| [v1.0.0 - Stable Release](https://gitlab.com/devnw/zig/config/-/milestones/4) | API stability, full coverage |

## Good First Issues

Looking for a place to start? Check these issues:

- [#1 - Add LICENSE file](https://gitlab.com/devnw/zig/config/-/issues/1)
- [#2 - Add CHANGELOG.md](https://gitlab.com/devnw/zig/config/-/issues/2)
- [#23 - Update project description and topics](https://gitlab.com/devnw/zig/config/-/issues/23)

## Merge Request Guidelines

1. Create a branch from `main`
2. Make focused, atomic commits
3. Write clear commit messages
4. Add tests for new functionality
5. Update documentation as needed
6. Link the related issue in MR description
7. Request review from maintainers

### MR Title Format

```
type(scope): description

Examples:
feat(loader): add command-line flag parsing
fix(dotenv): implement apply() function
docs(readme): add configuration examples
```

## Testing Requirements

All merge requests must:

- [ ] Pass existing tests
- [ ] Add tests for new functionality
- [ ] Maintain or improve coverage

See: [#14 - Add test coverage reporting](https://gitlab.com/devnw/zig/config/-/issues/14)

## Documentation

- Update README.md for user-facing changes
- Add doc comments for all public APIs
- Update docs/ for architectural changes

See: [#21 - Add API documentation generation](https://gitlab.com/devnw/zig/config/-/issues/21)

## Release Process

1. All milestone issues completed
2. All tests passing
3. Documentation updated
4. CHANGELOG.md updated
5. Version bumped in build.zig.zon
6. Tag created and pushed

## Questions?

- Open an issue for questions
- Check existing documentation
- Review closed issues for context

## Code of Conduct

Be respectful, constructive, and professional in all interactions.
