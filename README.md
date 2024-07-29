# Basic Chaum-Pedersen Zero Knowledge Proof implementation

## Overview

This repo contains a very basic implementation of a ZK proof auth client and server (prover and verifier) which implements the Chaum–Pedersen Protocol. Both the prover and the solver are coded using Rust and are built into separate binaries whcih communicate between each other using gRPC.

## How it works

The implementation of this library uses discreet logarithm computation where the prover and verifier both agree on a discreet group of prime order as well as two generators for it. Therefore as a pre-requisite both parties need to agree on the following well-known values:

* `p` - a prime number, used for the modulus of the discreet group `G`. In a real application this needs to be a very large prime number.
* `q` - `q = |G|` is the order of the group
* `g` and `h` are of prime order and as such `g ^ q mod p = 1` and `h ^ q mod p = 1`

Once the above pre-requisite/steup step is completed there are 3 steps required to stablish a secure ZKP authentication:

1. **Registration step** - the prover "registers" with the prover. During this step the prover chooses a secret (big) number _x_ and with it calculates two numbers y1, y2. Then these numbers are shared with the verifier (whithout shint _x_)
2. **Commitment -> Challenge step** - the prover initiates an authentication attempt by choosing a (very big) random number _k_ which is then used to calculate two values r1 and r1. R1 and r2 are then sent to the verifier (without sharing _k_). In the response the verifier returns a randomly generated number _c_.
3. **Verification step** - the prover uses the challenge _c_ from the previous step and its secret _x_ to calculate a solution _s_ whcih is sent to the verifier. Then the verifier calculates a new number using _y1_, _y2_, _r1_, _r2_, _c_ and _s_ to verify if the prover indeed knows _x_ without ever revealing it.  

## Assumptions and comments

### Simplifications and shortcuts taken

This code is simplified and is not suitable for production use. Its purpose is only to demonstrate use of the Chaum-Pedersen ZKP protocol. A more production ready solution would require a number of improvements. For example, to name a few:

* The client and server would communicate over TLS
* Proper observability instrumentation needs to be added (metrics, tracing, logs, dashboards/alerts as code etc.)
* Proper documentation
* The ZKP protocol would be exported as a library which can then be used from different client and server implementations and communication protocols (i.e. not just gRPC)
* External storage for the users, challenges needs to be used instead of an in-memmory map which doesn't scale
* Use proper session_id token, e.g. JWT. Returning just random string is not appropriate for production without at least checking if the string is unique or not
* Disallow registering a username more than once for obvious reasons. For simplification reasons in the current implementation, the entry in the users hashmap is overridden if it already exists which is not secure at all.
* The client would accept the username and secret from configuration (e.g. environment variable or a config file) or user input instead of hard-coding them in the code.
* Build the docker images for multiple platforms.

### Unit tests

Some unit tests of the main functionality (i.e. the `solve` and `verify` methods) have been added, however, production-grade code would require a higher level of coverage.

### Functional tests of the ZKP protocol

Some functional tests have been added which test the process of registration, atuh challenge and verification. The set of tests is by no means compelte and doesn't involve all happy and unhappy paths.

### Client and Server setup

Assuming that Docker is present on your machine, the client and the server can be started by running using the `docker-compose.yaml` file:

```bash
$ docker compose up
[+] Running 2/0
 ✔ Container zkp-auth-server-1  Created                                                                              0.0s
 ✔ Container zkp-auth-client-1  Created                                                                              0.0s
Attaching to client-1, server-1
server-1  | Listening for connections on 0.0.0.0:50051
client-1  | Registration successful.
client-1  | Received challenge from server.
client-1  | Successfully logged in! Session ID: OooJ8n7FOOU1ZyhxOqfBhsvK5x4mwdP7
client-1 exited with code 0
```

Alternatively, if Docker is not available, one can always run the binaries using `cargo` like this:

* Run `cargo run --bin zkpauth-server` in one terminal; and then
* Run `cargo run --bin zkpauth-client` in another terminal

By default the server listens on and the client tries to connect to `127.0.0.1:50051`.

### Performance and optimizations

There is room for improvement in terms of performance optimizations. In a production grade code it would be appropriat to use [Profile-guided Optimizations](https://doc.rust-lang.org/rustc/profile-guided-optimization.html) as well as add [benchmarks](https://nnethercote.github.io/perf-book/benchmarking.html) to ensure that the performance of every iteration of the code is not worse than the previous in terms of performance.

### Cloud deployment

In the repo there are GitHub workflow actions which create cloud infrastructure on AWS as well as build and deploy containers of the client and server to the cloud.

### Using BigUint numbers

In order for the protocol to be more secure really big numbers need to be used. This is the reason why this implementation uses BigUint instead of int64 for example.

### TODOs

* Add a _prover_ and a _verifier_ traits so that multiple implementations can be added
* Use elliptic curves - Instead of using discrete logarithms the protocol could be changed to use a well known elliptic curve. Then instead of providing numbers y1, y2 and r1, r2 etc. each number would need to replaced with the x and y coordinate of a point on the elliptic curve. One can use one of the elliptic curves from one of the TLS libraries. Further reading:
  * [Zero-Knowledge Proof - Cryptographic Primitives and Sigma Protocol](https://www.byont.io/blog/zero-knowledge-proof-cryptographic-primitives-and-sigma-protocol)
  * [Elliptic curves](https://crypto.stackexchange.com/questions/105889/chaum-pedersen-protocol-adapted-to-elliptic-curves?noredirect=1#comment226693_105889)
* Add observability (e.g. Prometheus metrics, tracing, structured logging and Grafana dashboards).

## Resources

* [Explanation video](https://www.youtube.com/watch?v=fOGdb1CTu5c)
* [Basic example explained](https://crypto.stackexchange.com/questions/99262/chaum-pedersen-protocol)
* [Primitive modulo](https://en.wikipedia.org/wiki/Primitive_root_modulo_n#Definition_and_examples)
* [RFC3526 - Groups](https://www.rfc-editor.org/rfc/rfc3526#page-3)
* [RFC5114 - Groups](https://www.rfc-editor.org/rfc/rfc5114#page-15)
