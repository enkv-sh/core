# Application dotenv consumer fixture

This local fixture checks independently specified synthetic file bytes against
the default `parse` function in `motdotla/dotenv` 18.0.9. It compares the complete
own-key set and every UTF-8 value byte. Parser characterization cases also record
the transformations that the encoder must avoid. The literals in `vectors.json`
are derived by applying the documented emission table directly; the production
encoder does not generate them.

Install the exact test-only dependency before qualification:

```sh
npm ci --ignore-scripts --no-audit --no-fund --prefix tests/fixtures/dotenv-consumer
```

Run `TestMaterializationEnvPinnedConsumer` through the repository test launcher.
The check requires Node v24.19.0 and the installed fixture. It fails if either is
missing or the Node version differs. It makes no network request. Its safe result
records the actual Node version,
the pinned package version and the number of checked vectors. It uses no real
values and prints no file content or decoded value. The pure encoder tests do
not need Node. This fixture establishes no shell, Docker or expansion behavior.
