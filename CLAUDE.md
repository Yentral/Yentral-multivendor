# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

This repo is a thin wrapper around a Medusa 2.0 application that demonstrates a multi-vendor marketplace. The actual marketplace logic does **not** live in this repo — it has been moved into the external [`@techlabi/medusa-marketplace-plugin`](https://github.com/Tech-Labi/medusa-marketplace-plugin) (see `medusa-config.ts`), and this project consumes it as an npm dependency.

- `medusa-marketplace-demo/` — the Medusa app (where all `yarn`/`medusa` commands run).
- `docker-compose.yml` — PostgreSQL only (creates an external Docker network named after `PROJECT_NAME`, default `marketplace`).
- `docker-compose.medusa.yml` — Medusa container; **requires** the network from the main compose file to already exist.

## Common commands

All commands run from `medusa-marketplace-demo/` unless noted.

```bash
# First-time setup
yarn
cp .env.template .env
npx medusa db:setup --db marketplace   # creates DB + runs migrations
yarn seed                              # optional: src/scripts/seed.ts (regions, products, sales channel, API key)

# Day-to-day
yarn dev                               # medusa develop (admin at http://localhost:9000/app)
yarn build                             # medusa build (outputs to .medusa/)
yarn start                             # medusa start (production)

# Migrations after editing modules or links
npx medusa db:generate <module-name>
npx medusa db:migrate

# Run a CLI script
npx medusa exec ./src/scripts/<file>.ts [args...]

# Tests (jest config switches test set via TEST_TYPE)
yarn test:unit                         # **/src/**/__tests__/**/*.unit.spec.ts
yarn test:integration:modules          # **/src/modules/*/__tests__/**/*
yarn test:integration:http             # **/integration-tests/http/*.spec.ts

# Run a single test file
TEST_TYPE=integration:http NODE_OPTIONS=--experimental-vm-modules \
  yarn jest integration-tests/http/health.spec.ts --runInBand --forceExit
```

### Docker

PostgreSQL must be up before starting the Medusa container — `docker-compose.medusa.yml` declares the network as `external: true`.

```bash
docker compose up                                                # PG only
docker compose -f docker-compose.yml -f docker-compose.medusa.yml up --build
docker compose -f docker-compose.yml -f docker-compose.medusa.yml down -v
```

`.env.docker` (mounted into the container) hard-codes `DATABASE_URL=postgres://marketplace:super-secure-password@postgres:5432/marketplace`. Local `.env` (from `.env.template`) instead uses `localhost`.

## Architecture notes that span files

- **Marketplace plugin coupling.** `medusa-config.ts` registers `@techlabi/medusa-marketplace-plugin` under `plugins`. The plugin ships its own admin extensions and patches the Medusa admin at install time via the `postinstall` script in `package.json`:
  `node node_modules/@techlabi/medusa-marketplace-plugin/.medusa/server/src/patch-admin.js`.
  If `yarn` is skipped or `node_modules` is wiped, admin pages from the plugin will not appear. Re-run `yarn` to re-apply the patch.
- **Vite/admin tweak.** `medusa-config.ts` adds `qs` to `optimizeDeps.include` for the admin Vite build — this is required for the plugin's admin pages to load and should not be removed.
- **File-based conventions (Medusa 2).** Each subdirectory under `src/` maps to a Medusa concept by convention; create new files matching the pattern rather than wiring imports manually:
  - `src/api/**/route.ts` — REST endpoints (export `GET`/`POST`/etc.); `[param]` directories become path params; `src/api/middlewares.ts` registers per-route middleware.
  - `src/modules/<name>/{models,service.ts,index.ts}` — custom modules with their own data models. After adding/changing models run `npx medusa db:generate <name>` then `npx medusa db:migrate`.
  - `src/links/*.ts` — `defineLink(...)` between data models in different modules; `npx medusa db:migrate` syncs them.
  - `src/workflows/*.ts` — composed `createWorkflow`/`createStep` units; invoke from API routes/jobs/subscribers.
  - `src/subscribers/*.ts` — event handlers (`config.event = "product.created"` etc.).
  - `src/jobs/*.ts` — cron jobs (`config.schedule`).
  - `src/admin/widgets/*` and `src/admin/routes/*` — admin React UI extensions (`defineWidgetConfig`, `defineRouteConfig`).
  - `src/scripts/*.ts` — runnable via `npx medusa exec`.
- **Container-driven DI.** Inside API routes use `req.scope.resolve(...)`; inside scripts/workflows/jobs use `container.resolve(...)`. Resolve modules either by string id (`"product"`) or via `Modules.<NAME>` / `ContainerRegistrationKeys.*` from `@medusajs/framework/utils`. `seed.ts` is the canonical example of using core workflows + the container.
- **Tests.** A single `jest.config.js` selects which test set runs based on `TEST_TYPE`. HTTP integration tests use `medusaIntegrationTestRunner` from `@medusajs/test-utils` with `inApp: true` (boots the app in-process — see `integration-tests/http/health.spec.ts`).
- **TypeScript.** Root `tsconfig.json` targets the server (`Node16`, decorators, output to `.medusa/server`). `src/admin/tsconfig.json` is a separate browser-side config (`bundler` resolution, strict, `noEmit`) — keep admin code compatible with both.
- **Instrumentation.** `instrumentation.ts` is the OpenTelemetry hook point — disabled by default, uncomment to enable.

## Branching

Develop and push to `claude/add-claude-documentation-2flGZ`. Do not push elsewhere without explicit permission.
