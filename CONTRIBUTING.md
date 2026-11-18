# Contributing

This project has one maintainer. Issues and patches are welcome, and are
read by the person who wrote the code; there is no promised time to an
answer.

## A flaw in a defence

Not here. Report it privately: [SECURITY.md](SECURITY.md).

## An issue

Open one for a bug, for a document that says something the code does not
do, or for something [docs/limits.md](docs/limits.md) should say and does
not. The most useful report names the command that was run, the platform
(`uname -sm`) and what was printed. Linux on x86_64 and on arm64 are tested
on every commit; macOS on arm64 is where the code is written.

## A patch

This tree is written by a script from a private repository, one commit per
export (`PROVENANCE.json` names the commit), so a pull request cannot be
merged here as it is: the next export would write over it. What happens
instead:

1. Open the pull request. The checks in `.github/workflows/ci.yml` run on
   it.
2. If it is taken, the maintainer applies it in the private repository,
   with you named as co-author of the commit, and it arrives here with the
   next export. The pull request is then closed with a link to that commit.
3. If it is not taken, the pull request says why.

Before opening one:

```bash
make lint          # rustfmt and clippy, warnings refused
make test          # every test that needs no service
make docs-check    # the documents name only what the tree has
make demo          # if the change touches the worker, the gates or the controller
```

A change to what a module, a worker or somebody on the bus is refused comes
with a test that fails without it, and with its line in
[docs/threat-model.md](docs/threat-model.md) or
[docs/limits.md](docs/limits.md).

Some files are derived and are changed at their source: the file itself
says so in its first lines (`deploy/nats/worker-permissions.conf`, for
one).

## Licence

The tree is licensed under either of Apache-2.0 or MIT, at your option. A
contribution you submit is taken under the same two licences, with no other
terms.
