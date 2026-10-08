# Attack Path Analysis: Current Scope

Osprey does not currently discover cloud identities, IAM permissions, Kubernetes service accounts, deployed workloads, or cloud storage. A source route declaration or a high-severity package finding is not enough to construct an attack path.

The normal backend attack-path service therefore returns no cloud attack path unless the supported analysis has relevant explicit evidence. The optional flagship demo seeds fictional Internet, endpoint, identity, and S3 nodes and is labeled simulated. Those fixture nodes are not reusable production facts.

## What can be established now

- A static HTTP route declaration in supported source syntax, with file and line.
- A local call path from an observed handler to a call to an advisory-mapped symbol, when all relevant functions are in the submitted source bundle and syntax is supported.
- A user-supplied endpoint profile, labeled as a user assertion with evidence.

## What remains unknown

- Whether a route is reachable from the public internet.
- Authentication and gateway enforcement unless separately supplied as an assertion.
- Whether a component or process is deployed/running.
- Whether the process has cloud credentials, what those credentials can access, or whether an exploit succeeds.

Future attack-path edges must carry source evidence and confidence. Missing hops should remain unknown rather than being filled from a demo topology.
