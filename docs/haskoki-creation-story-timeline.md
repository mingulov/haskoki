# Haskoki development timeline

The project grew from a loadable module into a token people could try.
This table follows the development work; it is not a list of separately
published releases. September 20 comes from the [changelog](../CHANGELOG.md)
and the original workspace history. The public repository begins with
[the September 24 import](https://github.com/mingulov/haskoki/commit/2cd3f37).

| When, in 2026 | What changed | Why it mattered |
| --- | --- | --- |
| September 20 | First C-loadable module, PKCS#11 function tables, and a small SHA-256 path | Established that ordinary clients could load the Haskell implementation. |
| September 21-23 | Sessions, objects, a behavior model, client tests, and bundle packaging | Turned the loader experiment into a token; 106 mechanisms had behavior tests at this stage. |
| September 24-25 | Repository import and external-checker triage | Client calls exposed gaps in errors, parameters, and lifecycle handling. |
| September 25-26 | More ciphers, curves, and post-quantum algorithms | Added crypto families in small slices, each with its own checks. |
| September 27-30 | Coverage sweep to 316 of 464 catalog mechanisms | Made the tested, unsupported, and planned parts visible in one inventory. |
| September 30 | Proxy differences and warning cleanup | Addressed differences between direct loading and the separate-process route. |
| September 30 | PKCS#11 message operations and 3.2 async routing | Connected newer interfaces to actual C calls, with explicit scope limits. |
| October 1 | Slot notifications and callbacks | Exercised token presence changes, waiting clients, and callback behavior. |
| October 1-2 | Certificate objects | Added persistent public objects and checks for their attributes and lifecycle. |
| October 2-3 | Further mechanism routes and native-boundary review | Worked through buffer handling, ownership, and refusal cases. |
| October 4-6 | Demo, coverage publication, checker profiles, and proxy qualification | Prepared repeatable examples and recorded the remaining differences. |
| October 7-8 | Security fixes, dependency and CI checks, release packaging | Reduced the demo's full-checker findings from 27 to 22 and tested the artifacts. |
| October 9 | First public release, v0.3.0.0 | Published the native bundle, source archive, checksums, reports, and Docker image. |
| v0.3.1.0 preparation | Shorter onboarding, a prepared shell, pkcs11-tool examples, and p11-kit remoting | Makes a first demo easier to run and understand; publication is a separate step. |

The [coverage](coverage.md) and [results](release-results.md) pages give
current counts and limitations. Earlier measurements in those records
belong to their stated revisions. Calendar dates do not measure personal
working hours, and the [AI-usage account](haskoki-creation-story-costing.md)
uses model-call timestamps rather than commit dates.

Read the [creation story](haskoki-creation-story.md) for the reasoning
behind these stages, or [try the demo](../README.md#try-it-with-docker).
