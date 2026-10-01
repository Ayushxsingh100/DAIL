# ADR-014: core.terraform_model may import core.domain
**Status:** Accepted (C-27, 30 Sep 2026).

**Context.** The P3a parser and normalizer must build `core.domain` value
objects (`Resource`, `Reference`, `Provenance`), and the TerraPreserve
pipeline reuses the same package (ADR-013), so its only core dependency is
the domain. The implementation guide says `core/terraform_model` imports "no
other core engines". Rule R6 in `tests/contract/test_architecture_boundaries.py`
was written more strictly than that text: it forbade every other `core.*`
package, including `core.domain`, which would have forced the normalizer to
duplicate the domain types.

**Decision.** Rule R6 is amended. `core.terraform_model` may import the
standard library except `sqlite3`, and `core.domain.*`. It may not import any
other `core.*` package (identity, dependency, impact, verification,
promotion, application) or `evidence`. R7 still forbids third-party packages.
The contract test enforces this, with self-test cases that fail on a breaking
source and a case that shows `core.domain` imports are accepted.

**Consequences.** The normalizer can produce domain `Resource` objects
directly and stays free of persistence, engines and application code. A later
need to import any other core package from `core.terraform_model` needs its
own ADR.
