# The SQL corpus

`statements.sql` is one SQL statement per line (made-up tables and values).
Each of the four gates caller-written SQL passes records its verdict for every
line:

| Snapshot | Gate | Test |
|---|---|---|
| `classify.snapshot` | `aegix_sql_classify::classify` — read, write, or neither | `aegix-sql-classify/tests/corpus.rs` |
| `worker.snapshot` | the worker's `validate_sql_with_policy`, under three allowlist configurations | `aegix-wasm-host/tests/sql_corpus.rs` |
| `controller.snapshot` | the controller's admission functions for `talos.database.query` | the platform's `aegix-rpc-subscribers` crate, `sql_corpus_tests` |
| `query_paginated.snapshot` | `aegix_admin_query_gate`, the platform-admin `query_paginated` tool: `T=` its text rules, `P=` its parsed gate on its own (the tool runs a statement only when both say `ok`) | the platform's `aegix-admin-query-gate` crate, `sql_corpus` |

The worker, the controller and `query_paginated` ask one function allow list
(`aegix_workflow_job_protocol::ALLOWED_SQL_FUNCTIONS`, 2026-10-08) through one
walk (`aegix_sql_classify::first_function_not_admitted`), so a change to the
list moves verdicts in three snapshots at once.

A test fails when a verdict differs from its snapshot, and prints each
difference. That is the point: the gates are built on `sqlparser`'s syntax
tree, and a new release can parse a statement it used to refuse, or parse one
differently — silently changing what a gate admits.

## When a snapshot test fails

A changed verdict is a decision, not noise. Read each one:

* **refused → admitted** must be argued for. Nothing here should start being
  admitted because the parser learned new syntax.
* **admitted → refused**, or one refusal reason for another, is usually fine;
  say why in the change.

Then record the new verdicts and commit the snapshots with the change:

```bash
SQL_CORPUS_BLESS=1 cargo test -p aegix-sql-classify --test corpus
SQL_CORPUS_BLESS=1 cargo test -p aegix-wasm-host --test sql_corpus
SQL_CORPUS_BLESS=1 cargo test -p aegix-rpc-subscribers --lib sql_corpus_tests
SQL_CORPUS_BLESS=1 cargo test -p aegix-admin-query-gate --test sql_corpus
```

`git diff aegix-sql-classify/corpus/` is then the review. The last two
commands name the platform's crates; a tree without them records the first two.

## What a re-recorded snapshot cannot hide

Beside each snapshot comparison is a test that asserts a rule per statement,
from the SQL text and not from the snapshot: with no operation granted the
worker admits nothing that names a write; an `INSERT`-only grant admits no
other write; what the controller calls a read carries no write and creates no
table; what `query_paginated`'s parsed gate admits on its own names no write, no
`pg_` word, no system schema, no withheld table and no function the deny lists
pin. Re-recording a snapshot does not make those pass.

## Adding a statement

Add the line, re-record, and look at the four new verdicts. Add one whenever
a gate is found admitting something it should not — the corpus found such
statements the day it was written (2026-10-06; recorded in the development repository's engineering log,
`2026-10-06-sql-gates-carried-statements-and-select-into.md`).
