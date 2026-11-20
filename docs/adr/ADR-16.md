# ADR-16 — DER read-back origin

Status: Accepted

**Decision:** reads serve stored components verbatim; DER is
assembled at write/keygen time, never decoded on read
(`core/Haskoki/Der.hs`: writers assemble PKCS#8/SPKI purely from
components; `finishWork` stamps components back so reads serve them
without a decode path). Per-attribute DER decode-on-read is
explicitly untraced by design, not an oversight.

**Rejected:** decode-on-read paths; DER-sourced attribute reads;
encoding half-understood structures (foreign curves refuse
`CKR_CURVE_NOT_SUPPORTED`, malformed parts refuse
`CKR_TEMPLATE_INCONSISTENT`).

**Consequence:** read-back semantics stay component-grounded; DER
scope stays narrow (RSA/SEC1/DSA/Edwards/Montgomery/ML-DSA/ML-KEM
as coded).

**Wrong if:** a named consumer needs DER-sourced reads — then the
per-attribute path is traced first (R-08), and this record gains a
successor.
