//! Which SQL functions a statement may call: the deny list, the families
//! denied by prefix, the allow list, and what a guest module's SQL is
//! further refused.
//!
//! The controller's gates and the worker's validator read the same lists,
//! which is why they are in the crate both link. They are not part of any
//! message. Moved out of `lib.rs` 2026-11-18, unchanged; every item is
//! re-exported at the crate root, where it was.

/// Postgres function names that caller SQL must never invoke.
///
/// **A PIN since 2026-10-08, not the policy.** The policy is the allow list,
/// [`ALLOWED_SQL_FUNCTIONS`] asked through [`is_allowed_sql_function`]; no
/// gate asks this list any more. It stays as the record of what was found
/// dangerous and why, and a test holds the allow list to it: nothing named
/// here, nothing in a [`DISALLOWED_SQL_FUNCTION_PREFIXES`] family and
/// nothing in [`SQL_TEXT_EVALUATOR_FUNCTIONS`] may ever be admitted. The text
/// below describes the deny list as it was used until then.
///
/// **Why a function deny-list is needed.** The statement-level deny-list
/// blocks `COPY`, `SET ROLE`, `PREPARE`, etc. — but a benign-looking
/// `SELECT pg_read_server_files('/etc/passwd')` parses as a Query and
/// passes every other gate. The validator must walk `Expr::Function`
/// nodes inside SELECT bodies and refuse any whose unqualified name (or
/// `pg_catalog.*` qualified form) appears below.
///
/// **Three risk classes:**
///
/// 1. **Filesystem read.** `pg_read_server_files` / `pg_read_file` /
///    `pg_read_binary_file` / `pg_ls_dir` / `pg_stat_file` /
///    `pg_ls_logdir` / `pg_ls_waldir` / `pg_ls_archive_statusdir` /
///    `pg_ls_tmpdir` — read arbitrary files on the database host. The
///    `talos_guest` role wrap (M-2) revokes EXECUTE where possible, but
///    PUBLIC keeps the default grant on many of these in stock
///    PostgreSQL — relying on the role alone is fragile. Block AST-side
///    for defense in depth.
///
/// 2. **Sleep / budget burn.** `pg_sleep` / `pg_sleep_for` /
///    `pg_sleep_until` — consume the full `statement_timeout` (60 s
///    default) without releasing the controller-side semaphore permit
///    (`MAX_IN_FLIGHT = 8`). 8 concurrent sleeping queries from a
///    malicious actor stalls every other actor's DB RPC for the
///    timeout window. Combined with the 500 queries-per-execution
///    cap, the validator catches the DoS vector at parse time.
///
/// 3. **Backend / config manipulation.** `pg_terminate_backend` /
///    `pg_cancel_backend` — kill arbitrary Postgres sessions belonging
///    to other tenants. `pg_reload_conf` / `pg_rotate_logfile` —
///    operator-only maintenance ops. `lo_import` / `lo_export` —
///    large-object FS I/O (the LO equivalent of `COPY FROM/TO`).
///
/// **Match rules:**
///
/// - Case-insensitive (Postgres normalises identifier case to lower for
///   unquoted identifiers; `PG_SLEEP(1)` is the same call as `pg_sleep(1)`).
/// - Matches both bare (`pg_sleep`) and schema-qualified (`pg_catalog.pg_sleep`)
///   forms — the visitor handles the schema strip before consulting this
///   list.
/// - Does NOT match user-defined functions with the same name. User code
///   that defines a `public.pg_sleep` is a footgun on its own (search_path
///   shadowing) and the validator can't disambiguate from the AST alone;
///   the role-wrap (M-2) is the fence for that case.
///
/// 4. **Session state that outlives the transaction.** Guest SQL runs
///    inside `BEGIN … COMMIT` on a POOLED connection, and two function
///    families leave state the transaction boundary does not clear —
///    denied by FAMILY in [`DISALLOWED_SQL_FUNCTION_PREFIXES`], not by
///    enumerating today's names. A SESSION-level advisory lock
///    (`pg_advisory_lock(k)`) survives COMMIT and ROLLBACK, so the
///    connection went back to the pool still holding it — for the rest
///    of that connection's life — and the controller takes its own
///    advisory locks on the same pool (budget admission, secret upsert,
///    the Google Calendar fleet lock). Large-object writers
///    (`lo_create`, `lo_from_bytea`, `lo_put`, `lowrite`) create rows in
///    `pg_largeobject` that outlive the transaction and every tenant
///    boundary: storage nothing reaps. `loread` / `lowrite` are the two
///    members spelled without the `lo_` prefix, so they are listed
///    exactly.
///
/// **Extending the list.** Adding a new entry requires updating both the
/// worker tests (`worker/src/sql_validator.rs`) and the controller-side
/// mirror tests (`aegix-rpc-subscribers`). The deliberate-duplication
/// comment in the subscriber documents why both sides exist.
pub const DISALLOWED_SQL_FUNCTIONS: &[&str] = &[
    // ── Filesystem read ─────────────────────────────────────────────────
    "pg_read_server_files",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "pg_ls_logdir",
    "pg_ls_waldir",
    "pg_ls_archive_statusdir",
    "pg_ls_tmpdir",
    // ── Sleep / budget burn ─────────────────────────────────────────────
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    // ── Backend control ─────────────────────────────────────────────────
    "pg_terminate_backend",
    "pg_cancel_backend",
    // ── Config / maintenance ────────────────────────────────────────────
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_promote",
    // ── Large object FS I/O (lo_import / lo_export) ─────────────────────
    // Also covered by the `lo_` FAMILY prefix below; kept by name because
    // they are the worst members (server-side filesystem I/O) and the
    // categorical tests name them.
    "lo_import",
    "lo_export",
    // ── Large-object members WITHOUT the `lo_` prefix ───────────────────
    // The rest of the family (`lo_create`, `lo_from_bytea`, `lo_put`,
    // `lo_open`, …) is denied by `DISALLOWED_SQL_FUNCTION_PREFIXES`.
    "loread",
    "lowrite",
    // ── adminpack filesystem write/delete ───────────────────────────────
    // The read side (pg_read_file/…) is covered above; adminpack adds the
    // MUTATION side, which is strictly worse. Typically not installed, but
    // denied in the same fail-closed spirit as dblink / plperlu below.
    "pg_file_write",
    "pg_file_read",
    "pg_file_unlink",
    "pg_file_rename",
    "pg_file_sync",
    "pg_logfile_rotate",
    "pg_logdir_ls",
    // ── dblink — bypass network egress controls via PG-side connection ──
    "dblink",
    "dblink_exec",
    "dblink_connect",
    // dblink_connect_u is the UNRESTRICTED variant — it lets a non-superuser
    // use any libpq auth method, the explicit privilege-bypass of
    // dblink_connect. Denying dblink_connect without it left the bypass open.
    "dblink_connect_u",
    "dblink_disconnect",
    "dblink_send_query",
    "dblink_open",
    "dblink_close",
    "dblink_fetch",
    "dblink_get_result",
    "dblink_get_connections",
    "dblink_cancel_query",
    "dblink_error_message",
    "dblink_is_busy",
    "dblink_get_notify",
    // ── PL/perl / PL/python untrusted variants — RCE via stored proc ────
    // These are typically not installed but if they ARE installed in the
    // operator's cluster, calling them from guest SQL is RCE.
    "plperlu_call_handler",
    "plpythonu_call_handler",
    "plpython3u_call_handler",
    // ── Session-state mutation — the FUNCTION form of the blocked SET ────
    // The statement-level deny-list blocks `SET` / `SET ROLE` /
    // `SET search_path` because (per its own rationale) they are
    // "session-level state mutation that can pivot privileges or change
    // query semantics for the rest of the connection". `set_config(name,
    // value, is_local)` is the FUNCTION equivalent — `SELECT
    // set_config('search_path', …, false)` / `set_config('role', …, false)`
    // / `set_config('statement_timeout', '0', false)` reach the exact state
    // the SET block prevents, but slip past it as a plain function call in a
    // SELECT. A WASM data query has no legitimate need to mutate session
    // config, so deny it fail-closed (the bare AND `pg_catalog.set_config`
    // forms are both caught by the matcher). `current_setting` (read-only)
    // is intentionally NOT blocked — it mutates nothing.
    "set_config",
    // ── Inter-session side channel — the FUNCTION form of blocked NOTIFY ─
    // The statement-level deny-list blocks `LISTEN` / `NOTIFY` / `UNLISTEN`
    // because they are inter-session side channels (a guest could signal or
    // exfiltrate to another connection out-of-band). `pg_notify(channel,
    // payload)` is the FUNCTION equivalent of the `NOTIFY` statement —
    // `SELECT pg_notify('chan', 'secret')` delivers the same async
    // notification, slipping past the statement gate as a plain function
    // call. Same parity gap as set_config↔SET (PR #114). There is no function
    // form of LISTEN/UNLISTEN to receive, but a one-way emit is still the
    // side channel the NOTIFY block exists to close. Denied fail-closed; a
    // WASM data query has no legitimate need to emit NOTIFY traffic.
    "pg_notify",
    // ── SQL-in-a-string evaluators (SPI) ────────────────────────────────
    // 2026-09-10 review. These take a QUERY as a string argument and run it
    // through SPI, so the expression-level deny-list above is blind to
    // whatever is inside the string: `query_to_xml('SELECT pg_sleep(29)',…)`
    // executes the sleep. Under the guest-role fence privileges are
    // unchanged (SPI inherits the role, and read-only SPI refuses DML), so
    // the effect there is budget burn — but on a deployment where
    // `AEGIX_RPC_GUEST_ROLE` is unset the whole validator is bypassed.
    // The worker carried these as a local supplement first; this is the ONE
    // home now so the controller-side `talos.database.query` subscriber
    // denies the same family. `xmltable` is XPath rather than SPI and is
    // kept out of conservatism.
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "table_to_xml",
    "table_to_xmlschema",
    "table_to_xml_and_xmlschema",
    "schema_to_xml",
    "schema_to_xmlschema",
    "schema_to_xml_and_xmlschema",
    "database_to_xml",
    "database_to_xmlschema",
    "database_to_xml_and_xmlschema",
    "xmltable",
    // 2026-10-08. The same class outside the SQL/XML family: functions
    // whose TEXT argument is a query the server runs for them. `ts_stat`
    // and the two-argument `ts_rewrite` are built in (text search) and were
    // measured to return another table's contents from inside a statement
    // every gate here called a read of nothing. Denied by NAME, so the
    // three-argument `ts_rewrite`, which runs no query, is refused with it:
    // an AST carries no argument types to tell the two apart.
    "ts_stat",
    "ts_rewrite",
    // `tablefunc` and `xml2` take a query as text the same way. Neither is
    // installed here; denied in the same fail-closed spirit as dblink.
    "crosstab",
    "crosstab2",
    "crosstab3",
    "crosstab4",
    "connectby",
    "xpath_table",
];

/// The members of [`DISALLOWED_SQL_FUNCTIONS`] that take SQL as TEXT and run
/// it. Named apart from the rest because a gate that reads the statement
/// cannot read the string: what such a function reaches is decided by the
/// role it runs as, never by the statement around it. Postgres has no
/// catalog column for "runs its argument"; this list is from reading the
/// server's sources (xml.c, tsvector_op.c, tsquery_rewrite.c) as of
/// Postgres 17 and the two contrib modules above.
pub const SQL_TEXT_EVALUATOR_FUNCTIONS: &[&str] = &[
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "ts_stat",
    "ts_rewrite",
    "crosstab",
    "crosstab2",
    "crosstab3",
    "crosstab4",
    "connectby",
    "xpath_table",
];

/// Function-name FAMILIES guest SQL must never invoke, matched as a
/// case-insensitive prefix of the (schema-stripped) name. Risk class 4 on
/// [`DISALLOWED_SQL_FUNCTIONS`]: state that outlives the guest's
/// transaction on a pooled connection.
///
/// * `pg_advisory_` / `pg_try_advisory_` — every advisory-lock function.
///   The SESSION-level ones survive COMMIT/ROLLBACK; the xact-level ones
///   are denied with them because a guest has no legitimate use for
///   either and a key that collides with the controller's own
///   `pg_advisory_xact_lock` callers blocks those paths for the length of
///   the guest's statement.
/// * `lo_` — every large-object function (`lo_create`, `lo_creat`,
///   `lo_from_bytea`, `lo_put`, `lo_open`, `lo_unlink`, `lo_get`, …).
///   Created objects persist in `pg_largeobject` after the transaction.
///
/// A PREFIX, not today's names, so a Postgres release that adds a family
/// member is denied the day it ships; the pinned list in this crate's
/// tests is what proves the prefix covers every name the server has
/// today. Deliberately narrow: `pg_` alone would deny `pg_typeof`, and
/// `lo` without the underscore would deny `lower` / `log`.
pub const DISALLOWED_SQL_FUNCTION_PREFIXES: &[&str] = &["pg_advisory_", "pg_try_advisory_", "lo_"];

/// The functions a caller's SQL may call: the ONE function policy for
/// module SQL (the worker's validator and the controller's re-parse of
/// `talos.database.query`) and for the platform-admin `query_paginated`
/// tool. Asked through [`is_allowed_sql_function`]; a function not named
/// here is refused, including one nobody has reviewed.
///
/// **What earns an entry.** A built-in Postgres 17 function that changes
/// nothing, reads no stored data beyond its arguments and the rows of the
/// statement, and does not execute SQL handed to it. The exceptions read
/// state outside the statement that reveals nothing stored: the clock
/// (`now`, `clock_timestamp`, …), randomness (`random`, `gen_random_uuid`)
/// and the transaction counter (`age(xid)`). Looking a name up is not
/// reading: the text search functions find their configuration by name, as
/// a cast finds its type. Nothing that returns catalog contents, a session
/// setting, the server's files or another session's state is here, and no
/// extension function is here.
///
/// **Names, not overloads.** A parsed statement carries no argument types,
/// so an entry admits every overload of its name. Each entry was checked
/// for every overload Postgres 17 has.
///
/// **Syntax that sqlparser parses as a call.** Some entries are not
/// functions in Postgres at all but syntax that sqlparser 0.63 reports as a
/// call by name: `array` (the `ARRAY(subquery)` constructor), `row`,
/// `coalesce`, `nullif`, `greatest`, `least`, the SQL-standard clock
/// keywords (`current_timestamp`, …) and the SQL/JSON constructors and
/// queries (`json_object`, `json_value`, …). Syntax sqlparser gives a node
/// of its own (`CAST`, `EXTRACT`, `SUBSTRING`, `TRIM`, `POSITION`,
/// `OVERLAY`, `CEIL`, `FLOOR`, `CASE`, `AT TIME ZONE`) is never reported as
/// a call and needs no entry (`aegix_sql_classify::try_for_each_called_function`).
///
/// **The deny lists are a PIN on this list, not the policy.** Nothing
/// [`DISALLOWED_SQL_FUNCTIONS`], [`DISALLOWED_SQL_FUNCTION_PREFIXES`] or
/// [`SQL_TEXT_EVALUATOR_FUNCTIONS`] covers may appear here; a test holds it.
///
/// **Adding an entry** is a security review of the function — every
/// overload — against the rule above, in a change that also re-records the
/// SQL corpus snapshots (`aegix-sql-classify/corpus/README.md`). The worker
/// and the controller must roll together: a worker with a longer list than
/// its controller forwards a call the controller then refuses.
///
/// Sorted within each group; lower case; plain identifiers only.
pub const ALLOWED_SQL_FUNCTIONS: &[&str] = &[
    // ── Aggregates ──────────────────────────────────────────────────────
    "any_value",
    "array_agg",
    "avg",
    "bit_and",
    "bit_or",
    "bit_xor",
    "bool_and",
    "bool_or",
    "corr",
    "count",
    "covar_pop",
    "covar_samp",
    "every",
    "grouping",
    "json_agg",
    "json_object_agg",
    "jsonb_agg",
    "jsonb_object_agg",
    "max",
    "min",
    "mode",
    "percentile_cont",
    "percentile_disc",
    "regr_avgx",
    "regr_avgy",
    "regr_count",
    "regr_intercept",
    "regr_r2",
    "regr_slope",
    "regr_sxx",
    "regr_sxy",
    "regr_syy",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "string_agg",
    "sum",
    "var_pop",
    "var_samp",
    "variance",
    // ── Window functions ────────────────────────────────────────────────
    "cume_dist",
    "dense_rank",
    "first_value",
    "lag",
    "last_value",
    "lead",
    "nth_value",
    "ntile",
    "percent_rank",
    "rank",
    "row_number",
    // ── String ──────────────────────────────────────────────────────────
    "ascii",
    "bit_length",
    "btrim",
    "char_length",
    "character_length",
    "chr",
    "concat",
    "concat_ws",
    "convert_from",
    "convert_to",
    "decode",
    "encode",
    "format",
    "initcap",
    "left",
    "length",
    "lower",
    "lpad",
    "ltrim",
    "normalize",
    "octet_length",
    "quote_ident",
    "quote_literal",
    "quote_nullable",
    "regexp_count",
    "regexp_instr",
    "regexp_like",
    "regexp_match",
    "regexp_matches",
    "regexp_replace",
    "regexp_split_to_array",
    "regexp_split_to_table",
    "regexp_substr",
    "repeat",
    "replace",
    "reverse",
    "right",
    "rpad",
    "rtrim",
    "split_part",
    "starts_with",
    "string_to_array",
    "string_to_table",
    "strpos",
    "substr",
    "to_hex",
    "translate",
    "upper",
    // ── Numeric ─────────────────────────────────────────────────────────
    "abs",
    "acos",
    "asin",
    "atan",
    "atan2",
    "cbrt",
    "ceiling",
    "cos",
    "degrees",
    "div",
    "exp",
    "gcd",
    "lcm",
    "ln",
    "log",
    "log10",
    "min_scale",
    "mod",
    "pi",
    "power",
    "radians",
    "round",
    "scale",
    "sign",
    "sin",
    "sqrt",
    "tan",
    "trim_scale",
    "trunc",
    "width_bucket",
    // ── Date and time ───────────────────────────────────────────────────
    "age",
    "clock_timestamp",
    "current_date",
    "current_time",
    "current_timestamp",
    "date_add",
    "date_bin",
    "date_part",
    "date_subtract",
    "date_trunc",
    "isfinite",
    "justify_days",
    "justify_hours",
    "justify_interval",
    "localtime",
    "localtimestamp",
    "make_date",
    "make_interval",
    "make_time",
    "make_timestamp",
    "make_timestamptz",
    "now",
    "statement_timestamp",
    "timezone",
    "transaction_timestamp",
    // ── Type conversion (formatting) ────────────────────────────────────
    "to_char",
    "to_date",
    "to_number",
    "to_timestamp",
    // ── JSON and JSONB: build and read ──────────────────────────────────
    "json_array",
    "json_array_elements",
    "json_array_elements_text",
    "json_array_length",
    "json_build_array",
    "json_build_object",
    "json_each",
    "json_each_text",
    "json_exists",
    "json_extract_path",
    "json_extract_path_text",
    "json_object",
    "json_object_keys",
    "json_populate_record",
    "json_populate_recordset",
    "json_query",
    "json_strip_nulls",
    "json_to_record",
    "json_to_recordset",
    "json_typeof",
    "json_value",
    "jsonb_array_elements",
    "jsonb_array_elements_text",
    "jsonb_array_length",
    "jsonb_build_array",
    "jsonb_build_object",
    "jsonb_each",
    "jsonb_each_text",
    "jsonb_extract_path",
    "jsonb_extract_path_text",
    "jsonb_insert",
    "jsonb_object_keys",
    "jsonb_path_exists",
    "jsonb_path_match",
    "jsonb_path_query",
    "jsonb_path_query_array",
    "jsonb_path_query_first",
    "jsonb_populate_record",
    "jsonb_populate_recordset",
    "jsonb_pretty",
    "jsonb_set",
    "jsonb_set_lax",
    "jsonb_strip_nulls",
    "jsonb_to_record",
    "jsonb_to_recordset",
    "jsonb_typeof",
    "row_to_json",
    "to_json",
    "to_jsonb",
    // ── Arrays ──────────────────────────────────────────────────────────
    "array",
    "array_append",
    "array_cat",
    "array_dims",
    "array_length",
    "array_lower",
    "array_ndims",
    "array_position",
    "array_positions",
    "array_prepend",
    "array_remove",
    "array_replace",
    "array_to_string",
    "array_upper",
    "cardinality",
    "trim_array",
    // ── Conditionals and null handling ──────────────────────────────────
    "coalesce",
    "greatest",
    "least",
    "nullif",
    "num_nonnulls",
    "num_nulls",
    // ── Ranges ──────────────────────────────────────────────────────────
    "daterange",
    "int4range",
    "int8range",
    "isempty",
    "lower_inc",
    "lower_inf",
    "numrange",
    "range_merge",
    "tsrange",
    "tstzrange",
    "upper_inc",
    "upper_inf",
    // ── Row construction ────────────────────────────────────────────────
    "row",
    // ── UUID, randomness and hashing ────────────────────────────────────
    "gen_random_uuid",
    "md5",
    "random",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    // ── Text search that runs no query ──────────────────────────────────
    "array_to_tsvector",
    "numnode",
    "phraseto_tsquery",
    "plainto_tsquery",
    "querytree",
    "setweight",
    "strip",
    "to_tsquery",
    "to_tsvector",
    "ts_delete",
    "ts_filter",
    "ts_headline",
    "ts_rank",
    "ts_rank_cd",
    "tsvector_to_array",
    "websearch_to_tsquery",
    // ── Row generators ──────────────────────────────────────────────────
    "generate_series",
    "generate_subscripts",
    "unnest",
];

/// True iff a caller's SQL may call the function `name`, as
/// `aegix_sql_classify::CalledFunction::spelled` writes it: a bare name
/// (`lower`) or a `pg_catalog`-qualified one (`pg_catalog.lower`) whose
/// function part is in [`ALLOWED_SQL_FUNCTIONS`], compared without regard to
/// case (Postgres folds an unquoted name to lower case).
///
/// Refused: a name qualified by any other schema (`public.lower` is
/// whatever the deployment put there), a name of three or more parts, and a
/// name with a part that is not a plain identifier — which includes a
/// quoted part, so `"LOWER"(x)`, a different function to Postgres, is never
/// read as `lower`.
///
/// This is the ONE matcher every gate asks; never test
/// `ALLOWED_SQL_FUNCTIONS.contains(..)` directly.
pub fn is_allowed_sql_function(name: &str) -> bool {
    fn plain_identifier(part: &str) -> bool {
        let mut chars = part.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
    let function = match name.split('.').collect::<Vec<_>>().as_slice() {
        [bare] => *bare,
        [schema, function] if schema.eq_ignore_ascii_case("pg_catalog") => *function,
        _ => return false,
    };
    plain_identifier(function)
        && ALLOWED_SQL_FUNCTIONS.contains(&function.to_ascii_lowercase().as_str())
}

/// Functions on [`ALLOWED_SQL_FUNCTIONS`] that module (guest) SQL may NOT
/// call: each builds a value or a set whose size the caller chooses, and the
/// server materialises it before any result cap is consulted —
/// `SELECT repeat('x', 1073741823) FROM generate_series(1, 1000)` asks for a
/// terabyte (security review 2026-10-14, D-3). The platform-admin
/// `query_paginated` tool keeps them ([`is_allowed_sql_function`]); a
/// module's `talos.database.query` asks [`is_allowed_guest_sql_function`].
/// Sorted, lower case, plain identifiers; every entry is on the allow list
/// (a test holds it).
pub const GUEST_EXCLUDED_SQL_FUNCTIONS: &[&str] = &[
    "generate_series",
    "generate_subscripts",
    "lpad",
    "repeat",
    "rpad",
];

/// [`is_allowed_sql_function`] for module (guest) SQL: the same matcher,
/// less [`GUEST_EXCLUDED_SQL_FUNCTIONS`]. The worker's validator and the
/// controller's re-check of `talos.database.query` both ask this one.
pub fn is_allowed_guest_sql_function(name: &str) -> bool {
    if !is_allowed_sql_function(name) {
        return false;
    }
    let function = name.rsplit('.').next().unwrap_or(name).to_ascii_lowercase();
    !GUEST_EXCLUDED_SQL_FUNCTIONS.contains(&function.as_str())
}

/// True iff `name` (case-insensitive, schema component already stripped)
/// appears in [`DISALLOWED_SQL_FUNCTIONS`] OR starts with one of the
/// [`DISALLOWED_SQL_FUNCTION_PREFIXES`] families. The schema strip is the
/// caller's responsibility — the AST visitor walks `ObjectName` and
/// passes the trailing identifier here, also re-checking the `pg_catalog`
/// qualified form because user code may write `pg_catalog.pg_sleep` to
/// bypass search-path tricks.
///
/// Until 2026-10-08 this was the ONE matcher both module-SQL gates called.
/// They now call [`is_allowed_sql_function`]; this matcher remains the
/// deny-list PIN's matcher, and the allow list's tests ask it. Never test
/// `DISALLOWED_SQL_FUNCTIONS.contains(..)` directly — that is the
/// exact-only match and misses every family.
///
/// Constant-time match isn't needed — function names are not secrets and
/// the entire deny-list is public. The linear scan over ~65 short strings
/// plus three prefixes is faster than the hash-table setup cost.
pub fn is_disallowed_sql_function(name: &str) -> bool {
    // Lowercase comparison. PG normalises unquoted identifiers to lower
    // at parse time, but sqlparser preserves the original case so we
    // normalise here for the comparison.
    let lower = name.to_ascii_lowercase();
    DISALLOWED_SQL_FUNCTIONS.contains(&lower.as_str())
        || DISALLOWED_SQL_FUNCTION_PREFIXES
            .iter()
            .any(|family| lower.starts_with(family))
}

// ============================================================================
// Wasm-security review 2026-05-22 (MEDIUM-1): SQL function deny-list tests
// ============================================================================
#[cfg(test)]
mod guest_sql_function_tests {
    use super::*;

    #[test]
    fn the_guest_list_is_the_admin_list_less_the_size_builders() {
        for f in GUEST_EXCLUDED_SQL_FUNCTIONS {
            assert!(is_allowed_sql_function(f), "{f} must be on the allow list");
            assert!(!is_allowed_guest_sql_function(f), "{f}");
            let upper = f.to_ascii_uppercase();
            assert!(!is_allowed_guest_sql_function(&upper), "{upper}");
            let qualified = format!("pg_catalog.{f}");
            assert!(!is_allowed_guest_sql_function(&qualified), "{qualified}");
        }
        assert!(GUEST_EXCLUDED_SQL_FUNCTIONS.windows(2).all(|w| w[0] < w[1]));
        for f in ["lower", "count", "pg_catalog.lower", "string_agg"] {
            assert!(is_allowed_guest_sql_function(f), "{f}");
        }
        for f in ["public.lower", "pg_sleep", "\"lower\""] {
            assert!(!is_allowed_guest_sql_function(f), "{f}");
        }
    }
}

#[cfg(test)]
mod disallowed_sql_function_tests {
    use super::{is_disallowed_sql_function, DISALLOWED_SQL_FUNCTIONS};

    /// A function that runs the SQL in its text argument is denied whichever
    /// family it belongs to. Until 2026-10-08 the list named the SQL/XML ones
    /// and not the text-search ones.
    #[test]
    fn every_function_that_runs_sql_it_is_handed_is_denied() {
        for f in super::SQL_TEXT_EVALUATOR_FUNCTIONS {
            assert!(DISALLOWED_SQL_FUNCTIONS.contains(f), "`{f}` is not listed");
            assert!(is_disallowed_sql_function(f), "`{f}` must be denied");
            assert!(
                is_disallowed_sql_function(&f.to_ascii_uppercase()),
                "`{f}` must be denied in upper case"
            );
        }
        for f in ["ts_stat", "ts_rewrite"] {
            assert!(super::SQL_TEXT_EVALUATOR_FUNCTIONS.contains(&f));
        }
        // Text search that runs no query stays available.
        for f in ["to_tsvector", "to_tsquery", "ts_rank", "ts_headline"] {
            assert!(!is_disallowed_sql_function(f), "`{f}` runs no query");
        }
    }

    #[test]
    fn every_canonical_entry_is_matched() {
        // Tripwire: if the const and the matcher ever drift the matcher
        // would silently miss entries the operator THOUGHT were blocked.
        for f in DISALLOWED_SQL_FUNCTIONS {
            assert!(
                is_disallowed_sql_function(f),
                "canonical deny-list entry `{f}` is not matched by is_disallowed_sql_function"
            );
        }
    }

    #[test]
    fn match_is_case_insensitive() {
        // PG normalises unquoted identifiers to lower; `PG_SLEEP(1)`,
        // `Pg_Sleep(1)`, and `pg_sleep(1)` are the same call. The
        // sqlparser AST may preserve original case, so the matcher
        // must normalise.
        assert!(is_disallowed_sql_function("PG_SLEEP"));
        assert!(is_disallowed_sql_function("Pg_Sleep"));
        assert!(is_disallowed_sql_function("pg_sleep"));
        assert!(is_disallowed_sql_function("PG_READ_SERVER_FILES"));
        assert!(is_disallowed_sql_function("LO_IMPORT"));
    }

    #[test]
    fn unrelated_function_names_not_matched() {
        // Tripwire against an overly-broad refactor (e.g. switching to
        // a `starts_with("pg_")` check that would block legitimate
        // user functions like `pg_my_custom_func`).
        for f in [
            "count",
            "sum",
            "now",
            "current_user",
            "json_agg",
            "row_number",
            "version",   // Note: version() is allowed (read-only info)
            "pg_typeof", // diagnostic, no escalation
            "pg_my_custom_business_func",
        ] {
            assert!(
                !is_disallowed_sql_function(f),
                "benign function `{f}` must NOT be matched by the deny-list"
            );
        }
    }

    #[test]
    fn empty_string_not_matched() {
        // Edge case: empty function name (shouldn't happen from the
        // parser, but defensively).
        assert!(!is_disallowed_sql_function(""));
    }

    #[test]
    fn deny_list_covers_three_risk_classes() {
        // Pin the categorical coverage so a future refactor that drops
        // any class (e.g. "let's only block filesystem reads") shows up
        // as a failing test rather than a silent policy regression.

        // Filesystem read
        for f in [
            "pg_read_server_files",
            "pg_read_file",
            "pg_read_binary_file",
            "pg_ls_dir",
            "pg_stat_file",
        ] {
            assert!(
                is_disallowed_sql_function(f),
                "filesystem-read `{f}` must be denied"
            );
        }

        // Sleep / budget burn
        for f in ["pg_sleep", "pg_sleep_for", "pg_sleep_until"] {
            assert!(is_disallowed_sql_function(f), "sleep `{f}` must be denied");
        }

        // Backend control / config
        for f in [
            "pg_terminate_backend",
            "pg_cancel_backend",
            "pg_reload_conf",
            "pg_rotate_logfile",
        ] {
            assert!(
                is_disallowed_sql_function(f),
                "backend-control `{f}` must be denied"
            );
        }

        // Large-object I/O + dblink network bypass
        for f in ["lo_import", "lo_export", "dblink", "dblink_connect"] {
            assert!(
                is_disallowed_sql_function(f),
                "io/dblink `{f}` must be denied"
            );
        }
    }
}

// ============================================================================
// The function allow list (2026-10-08) and its pin against the deny lists
// ============================================================================
#[cfg(test)]
mod allowed_sql_function_tests {
    use super::{
        is_allowed_sql_function, is_disallowed_sql_function, ALLOWED_SQL_FUNCTIONS,
        DISALLOWED_SQL_FUNCTIONS, DISALLOWED_SQL_FUNCTION_PREFIXES, SQL_TEXT_EVALUATOR_FUNCTIONS,
    };

    /// THE PIN. The deny lists stopped being the policy on 2026-10-08; they
    /// stay as the names the allow list must never admit, bare or
    /// `pg_catalog`-qualified, in any case.
    #[test]
    fn nothing_the_deny_lists_cover_is_admitted() {
        let pinned = DISALLOWED_SQL_FUNCTIONS
            .iter()
            .chain(SQL_TEXT_EVALUATOR_FUNCTIONS)
            .chain(super::disallowed_sql_function_family_tests::PG17_SESSION_STATE_FAMILY);
        for f in pinned {
            for spelled in [
                f.to_string(),
                f.to_ascii_uppercase(),
                format!("pg_catalog.{f}"),
                format!("PG_CATALOG.{}", f.to_ascii_uppercase()),
            ] {
                assert!(
                    !is_allowed_sql_function(&spelled),
                    "`{spelled}` is admitted"
                );
            }
        }
        for f in ALLOWED_SQL_FUNCTIONS {
            assert!(!is_disallowed_sql_function(f), "`{f}` is on both lists");
            for family in DISALLOWED_SQL_FUNCTION_PREFIXES {
                assert!(!f.starts_with(family), "`{f}` is in the `{family}` family");
            }
        }
    }

    #[test]
    fn every_entry_is_a_lower_case_plain_identifier_listed_once() {
        let mut seen = std::collections::HashSet::new();
        for f in ALLOWED_SQL_FUNCTIONS {
            assert!(seen.insert(*f), "`{f}` is listed twice");
            assert!(
                !f.is_empty()
                    && !f.starts_with(|c: char| c.is_ascii_digit())
                    && f.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "`{f}` is not a lower-case plain identifier"
            );
        }
    }

    /// Every entry is admitted bare and `pg_catalog`-qualified, in any case,
    /// because Postgres folds an unquoted name to lower case.
    #[test]
    fn every_entry_is_admitted_bare_and_pg_catalog_qualified() {
        for f in ALLOWED_SQL_FUNCTIONS {
            for spelled in [
                f.to_string(),
                f.to_ascii_uppercase(),
                format!("pg_catalog.{f}"),
                format!("Pg_Catalog.{f}"),
            ] {
                assert!(is_allowed_sql_function(&spelled), "`{spelled}` is refused");
            }
        }
    }

    /// Only a bare or a `pg_catalog` name is read. Any other schema is
    /// whatever the deployment put there; a quoted part is a different name
    /// to Postgres; anything else is not a name.
    #[test]
    fn only_a_bare_or_pg_catalog_name_of_plain_identifiers_is_admitted() {
        for spelled in [
            "public.lower",
            "myschema.lower",
            "db.pg_catalog.lower",
            "pg_catalog.pg_catalog.lower",
            "\"lower\"",
            "\"LOWER\"",
            "pg_catalog.\"lower\"",
            "\"pg_catalog\".lower",
            "",
            ".lower",
            "lower.",
            "lower ",
            " lower",
            "low-er",
            "lower()",
            "1lower",
            "unknown_function",
        ] {
            assert!(!is_allowed_sql_function(spelled), "`{spelled}` is admitted");
        }
    }
}

// ============================================================================
// Session-state families (advisory locks + large objects): denied by PREFIX
// ============================================================================
#[cfg(test)]
mod disallowed_sql_function_family_tests {
    use super::{
        is_disallowed_sql_function, DISALLOWED_SQL_FUNCTIONS, DISALLOWED_SQL_FUNCTION_PREFIXES,
    };

    /// EVERY `pg_catalog` function of the two families on PostgreSQL 17.11
    /// (the version `migrations/.baseline/schema.sql` is dumped from and the
    /// dev/CI image runs), read from the server rather than from docs:
    ///
    /// ```sql
    /// SELECT DISTINCT proname FROM pg_proc p
    ///   JOIN pg_namespace n ON n.oid = p.pronamespace
    ///  WHERE n.nspname = 'pg_catalog'
    ///    AND (proname LIKE 'pg\_advisory%' OR proname LIKE 'pg\_try\_advisory%'
    ///         OR proname LIKE 'lo\_%' OR proname IN ('loread', 'lowrite'))
    /// ```
    ///
    /// 29 names / 41 overloads (the lock functions each have a `(bigint)` and
    /// an `(integer, integer)` form). Migration
    /// `20260925160000_revoke_advisory_and_lo_from_public.sql` walks the same
    /// predicate, so this list and the REVOKE cover one population.
    pub(super) const PG17_SESSION_STATE_FAMILY: &[&str] = &[
        "lo_close",
        "lo_creat",
        "lo_create",
        "lo_export",
        "lo_from_bytea",
        "lo_get",
        "lo_import",
        "lo_lseek",
        "lo_lseek64",
        "lo_open",
        "lo_put",
        "lo_tell",
        "lo_tell64",
        "lo_truncate",
        "lo_truncate64",
        "lo_unlink",
        "loread",
        "lowrite",
        "pg_advisory_lock",
        "pg_advisory_lock_shared",
        "pg_advisory_unlock",
        "pg_advisory_unlock_all",
        "pg_advisory_unlock_shared",
        "pg_advisory_xact_lock",
        "pg_advisory_xact_lock_shared",
        "pg_try_advisory_lock",
        "pg_try_advisory_lock_shared",
        "pg_try_advisory_xact_lock",
        "pg_try_advisory_xact_lock_shared",
    ];

    #[test]
    fn every_pg17_family_member_is_denied_in_any_case() {
        for f in PG17_SESSION_STATE_FAMILY {
            assert!(is_disallowed_sql_function(f), "`{f}` must be denied");
            assert!(
                is_disallowed_sql_function(&f.to_ascii_uppercase()),
                "`{}` must be denied (Postgres folds unquoted identifiers)",
                f.to_ascii_uppercase()
            );
            // Mixed case: capitalise every other character.
            let mixed: String = f
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect();
            assert!(
                is_disallowed_sql_function(&mixed),
                "`{mixed}` must be denied"
            );
        }
    }

    /// The PREFIX is load-bearing, and this is the test that says so: most of
    /// the family is deliberately NOT in the exact list, so a refactor back to
    /// `DISALLOWED_SQL_FUNCTIONS.contains(..)` alone fails here rather than
    /// silently re-admitting `pg_advisory_lock`.
    #[test]
    fn the_family_is_denied_by_prefix_not_by_enumeration() {
        let prefix_only: Vec<&&str> = PG17_SESSION_STATE_FAMILY
            .iter()
            .filter(|f| !DISALLOWED_SQL_FUNCTIONS.contains(f))
            .collect();
        assert!(
            prefix_only.len() >= 20,
            "most of the family must be covered by the prefix alone, got {prefix_only:?}"
        );
        for f in &prefix_only {
            assert!(
                DISALLOWED_SQL_FUNCTION_PREFIXES
                    .iter()
                    .any(|p| f.starts_with(p)),
                "`{f}` is in neither the exact list nor a family prefix"
            );
            assert!(is_disallowed_sql_function(f), "`{f}` must be denied");
        }
        // A family member a FUTURE Postgres might add is denied today.
        for future in [
            "pg_advisory_lock_timeout",
            "pg_try_advisory_session_lock",
            "lo_compress",
        ] {
            assert!(
                is_disallowed_sql_function(future),
                "a new family member `{future}` must be denied by the prefix"
            );
        }
    }

    /// Real `pg_catalog` functions that share a stem with a family but are not
    /// in it (read from the same server: every `lo%` / `%advisory%` proname
    /// outside the families is one of `log`, `log10`, `lower`, `lower_inc`,
    /// `lower_inf`), plus the prefixes minus their separator. The prefixes end
    /// in `_` precisely so these stay callable.
    #[test]
    fn near_misses_are_not_denied() {
        for f in [
            "log",
            "log10",
            "lower",
            "lower_inc",
            "lower_inf",
            "lo",
            "pg_advisory",
            "pg_try_advisory",
            "pg_advisorylock",
            "pg_typeof",
        ] {
            assert!(
                !is_disallowed_sql_function(f),
                "`{f}` is not a family member and must stay callable"
            );
        }
    }
}
