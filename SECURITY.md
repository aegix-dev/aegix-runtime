# Reporting a flaw

Report it privately, through this repository's **Security** tab ("Report a
vulnerability"). Please do not open a public issue for something that lets a
module, a worker or somebody on the message bus get what it was not given.

**What is a flaw.** Anything [docs/threat-model.md](docs/threat-model.md) says
is refused and is not: a module reading a secret outside its grant, reaching
a host outside its list, writing above its actor's ceiling; a worker served
data for a job it is not running; a forged or replayed message that is
believed. A way to make the demo print a refusal that did not happen is one
too.

**What is not.** What [docs/limits.md](docs/limits.md) already says is not
defended. Tell us anyway if a limit is worse than it is written.

**What to expect.** This project has one maintainer, no bounty, and has had no
outside audit. Before 1.0 a fix is made in the newest release only. A report
is answered by the person who wrote the code, and a confirmed flaw is fixed,
released and named in `CHANGELOG.md` with credit to whoever found it, unless
they would rather not be named.
