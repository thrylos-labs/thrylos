# Consensus model

`Consensus.tla` is a finite abstraction of one height of the consensus
protocol. It checks two claims under the assumptions used by the Rust host:

- correct validators cannot decide two different values; and
- after the network becomes synchronous, a correct validator eventually
  decides.

The model covers quorum intersection, locks across rounds, Byzantine votes,
an arbitrary asynchronous prefix represented by symmetric rounds, and weak
fairness for correct validators after synchrony. Cryptography, canonical
encoding, execution validity, proposer selection and crash durability stay in
the Rust test suite; this model does not silently stand in for those checks.

Run the same command as CI from this directory:

```bash
curl -fsSL \
  https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar \
  -o tla2tools.jar
echo "85b172970b0a1d283b9e45679b8ecf5b4de72ab2  tla2tools.jar" | shasum -a 1 -c -
java -cp tla2tools.jar tlc2.TLC -workers 1 -config Consensus.cfg Consensus.tla
```

The jar is downloaded rather than committed and its upstream release checksum
is verified. CI runs one worker because the pinned TLC release documents a
past liveness-checking issue in its parallel worker path; formal evidence is
more useful than a faster ambiguous run.
