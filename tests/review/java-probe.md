# Independent Java token probe

`JavaTokenProbe.java` targets Java 17 or later. It configures SunPKCS11 from
its sole argument, logs in with `AuthProvider.login`, generates an EC P-256
session keypair, signs with `SHA256withECDSA` through that provider, and
verifies using an explicitly selected SunEC provider and a reconstructed
public key. A changed message must be rejected by SunEC. Signing has no
provider fallback. The private key is not exported.

Use the remote test runner's `default-jdk-headless` package. No local
compilation or execution was performed when preparing these files.

## Configuration contract

Write a SunPKCS11 configuration such as the following, substituting the
absolute path of the exact Haskoki artifact under test for `library`:

```text
name = HaskokiReview
library = /absolute/bundle/lib/libhaskoki.so
slot = 0
destroyTokenAfterLogout = true
attributes(generate, CKO_PUBLIC_KEY, CKK_EC) = {
  CKA_TOKEN = false
  CKA_PRIVATE = false
  CKA_VERIFY = true
}
attributes(generate, CKO_PRIVATE_KEY, CKK_EC) = {
  CKA_TOKEN = false
  CKA_PRIVATE = true
  CKA_SENSITIVE = true
  CKA_EXTRACTABLE = false
  CKA_SIGN = true
}
```

The Java process must inherit `HASKOKI_CONFIG` pointing to a valid native
Haskoki configuration. Prefer a fresh memory store for this probe. This
file is separate from the SunPKCS11 configuration passed as argv[0].
`HSK_REVIEW_USER_PIN` supplies the normal user's fixture PIN; if unset, it
defaults to `1234`. An explicitly empty value remains empty. Do not run
repeated incorrect-PIN probes against a reused persistent store.

## Exact invocation

From the source root, with `out/review-java` already created and
`/absolute/sunpkcs11.cfg` populated as above:

```sh
javac --release 17 -d out/review-java tests/review/JavaTokenProbe.java
java --add-modules jdk.crypto.cryptoki,jdk.crypto.ec -cp out/review-java JavaTokenProbe /absolute/sunpkcs11.cfg
```

The runner should place a bounded timeout around the Java command and save
stdout, stderr, exit status, `java -version`, the nonsecret SunPKCS11 config,
and the module's digest. Compilation failure is a harness failure, not a
token result. A timeout or native crash is also distinct from an emitted
Java failure record.

Exit 0 requires genuine verification, changed-message refusal and successful
logout, ending with `JAVA-PROBE PASS`. Exit 1 means an operation failed after
provider/oracle setup; exit 2 means setup failed; exit 3 means all operation
checks passed but logout failed. Every failure names its stage and nested
exception classes/messages. Login is an operation stage. Missing algorithm
support in the token therefore does not masquerade as a passing skip.

Cleanup always clears callback/PIN character arrays and attempts logout
after successful login, including after operation failure. The supplied
config requests session objects and provider token-resource disposal at
logout. The configured provider is passed directly to JCA calls and is
never registered in the global provider list. There is no portable JCA
`C_Finalize` call here: this probe does not establish native finalization,
durable storage, certificates, other mechanisms, or concurrent-client
compatibility. A failed login leaves native lifetime cleanup to process exit.

Oracle documents configuration, generated-key attributes and
`destroyTokenAfterLogout` in the [Java 17 PKCS#11 reference guide](https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html).
The callback login/logout contract is described by [AuthProvider](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/AuthProvider.html),
and reconstruction from encoded public-key material by [KeyFactory](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyFactory.html).
