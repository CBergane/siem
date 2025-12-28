# AI / Codex Working Agreement

## Goals
- Improve security and reliability without breaking existing functionality
- Add agent ingestion + service inventory safely
- Keep changes small and reviewable

## Non-goals
- No large refactors
- No renaming modules or changing public APIs unless asked

## Rules
1. Work in small commits / small diffs.
2. Do not modify database models unless explicitly requested.
3. Do not change existing endpoints behavior unless explicitly requested.
4. Never introduce secrets into the repo.
5. Prefer configuration via `.env` and `.env.example`.
6. Add/adjust tests when changing parsing/auth/crypto.
7. Provide a short "What changed" + "How to test" with each change.
8. Never change auth/crypto semantics without adding tests.
9. Avoid new dependencies unless necessary; if added, update requirements/lockfiles and docs.
10. Avoid running migrations automatically on container startup in dev unless explicitly requested.
11. For architecture decisions (multi-tenancy, agent registry), write a short doc before implementing.



## Preferred structure
- Scripts go in `scripts/`
- Docs go in `docs/`
- Security checks go in `scripts/` and referenced from docs
