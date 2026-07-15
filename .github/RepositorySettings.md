# GitHub Repository Settings

This document outlines the recommended settings for the public TaintFlow repository.

---

## General Settings
- **Repository Visibility**: Public.
- **Repository Features**:
  - **Issues**: Enabled (using YAML form templates).
  - **Discussions**: Enabled (for setup questions, rule ideas, and general discussion).
  - **Wikis**: Disabled (keep documentation versioned inside `docs/`).
  - **Projects**: Enabled (see [ProjectBoard.md](ProjectBoard.md)).

## Pull Requests Merge Configuration
To maintain a clean commit history:
- **Allow merge commits**: Disabled (prevents messy merge history).
- **Allow squash merging**: **Enabled** (default option for combining feature PRs into a single clean commit).
- **Allow rebase merging**: Enabled.
- **Automatically delete head branches**: **Enabled** (keeps the repository clean of stale branches).
