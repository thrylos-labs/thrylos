# Rough edges found while building the token example

Written 2026-09-26 while writing `examples/token`. Each is something a developer hits, not a bug in
the chain. Listed in the order they were met, with what would fix it.

1. **`move publish` needs `move build` first.** The error says so, but it is a step nobody wants to
   remember. *Fix:* `publish` builds when the package is not built or its sources are newer.
2. **A transfer names the recipient twice**: as an argument and again as `--input`. Forgetting the
   second aborts the call with a store code 3 that reads as "not declared". *Fix:* the CLI could
   offer `--touch-args` (declare every address argument), or say in the abort message which address
   it wanted declared.
3. **`view` is limited to one a second per node**, so a script reading three balances must sleep
   between them. The error says to try again in a second, which is honest, but a batch form
   (`view` with several calls) would remove the need.
4. **Views of another address need `--input` too**, for the same reason as 2, and the error for
   forgetting it is the store's, not the view's.
5. **The public nodes have `simulate` off**, so views do not work there yet; the example says
   `move resource` reads the same values anywhere.
6. **A token creator pays two deposits** (0.04 THRY) and the first receiver's drawer is paid by the
   sender; this is by design, and is written up in the example's README so it is not a surprise.
7. **`move resource` reads slot 0 unless told otherwise**, and when the drawer is empty the answer
   ("no ... is stored in slot 0") does not hint that another slot may hold it. A token keyed by an
   id lives at slot = id, so the first read of the token example, on the public chain, said nothing
   was there. *Fix:* on an empty slot, say which slots of that type the owner does hold (the node
   already keeps the drawers by owner).
