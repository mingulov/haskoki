import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AuthProvider;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/** Independent Java 17+ client probe; does not use Haskoki's model or test oracle. */
public final class JavaTokenProbe {
    private JavaTokenProbe() {}

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("JAVA-PROBE SETUP_FAIL stage=arguments usage=JavaTokenProbe CONFIG_FILE");
            System.exit(2);
        }

        char[] pin = System.getenv().getOrDefault("HSK_REVIEW_USER_PIN", "1234").toCharArray();
        List<PasswordCallback> passwords = new ArrayList<>();
        AuthProvider token = null;
        boolean loggedIn = false;
        boolean setupComplete = false;
        String stage = "configuration-file";
        int result = 0;
        try {
            Path config = Path.of(args[0]).toAbsolutePath();
            if (!Files.isRegularFile(config) || !Files.isReadable(config)) {
                throw new GeneralSecurityException("configuration file is not readable");
            }
            stage = "sunpkcs11-configuration";
            Provider bridge = Security.getProvider("SunPKCS11");
            if (bridge == null) {
                throw new GeneralSecurityException("SunPKCS11 provider is unavailable");
            }
            Provider configured = bridge.configure(config.toString());
            if (!(configured instanceof AuthProvider)) {
                throw new GeneralSecurityException("configured provider is not an AuthProvider");
            }
            token = (AuthProvider) configured;

            stage = "independent-verifier-setup";
            Provider sunEC = Security.getProvider("SunEC");
            if (sunEC == null) {
                throw new GeneralSecurityException("SunEC provider is unavailable");
            }
            KeyFactory publicKeys = KeyFactory.getInstance("EC", sunEC);
            Signature verifier = Signature.getInstance("SHA256withECDSA", sunEC);
            setupComplete = true;
            System.out.println("JAVA-PROBE SETUP_OK java=" + System.getProperty("java.version")
                    + " token=" + token.getName() + " verifier=" + verifier.getProvider().getName());

            stage = "login";
            token.login(null, callbacks -> {
                for (Callback callback : callbacks) {
                    if (!(callback instanceof PasswordCallback)) {
                        throw new UnsupportedCallbackException(callback, "expected PIN password callback");
                    }
                    PasswordCallback password = (PasswordCallback) callback;
                    passwords.add(password);
                    password.setPassword(pin);
                }
            });
            loggedIn = true;
            clearPasswords(passwords);
            System.out.println("JAVA-PROBE LOGIN_OK");

            stage = "ec-p256-generation";
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", token);
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();
            System.out.println("JAVA-PROBE KEYGEN_OK provider=" + generator.getProvider().getName());

            stage = "independent-public-key-import";
            byte[] encodedPublic = pair.getPublic().getEncoded();
            if (encodedPublic == null || encodedPublic.length == 0) {
                throw new GeneralSecurityException("token public key has no X.509 encoding");
            }
            PublicKey independentPublic = publicKeys.generatePublic(new X509EncodedKeySpec(encodedPublic));
            byte[] message = "Haskoki independent Java client probe v1".getBytes(StandardCharsets.UTF_8);

            stage = "sha256-ecdsa-sign";
            Signature signer = Signature.getInstance("SHA256withECDSA", token);
            signer.initSign(pair.getPrivate());
            signer.update(message);
            byte[] signature = signer.sign();
            if (signature.length == 0) {
                throw new GeneralSecurityException("token returned an empty signature");
            }
            System.out.println("JAVA-PROBE SIGN_OK provider=" + signer.getProvider().getName()
                    + " signatureBytes=" + signature.length);

            stage = "sunec-verify";
            verifier.initVerify(independentPublic);
            verifier.update(message);
            if (!verifier.verify(signature)) {
                throw new GeneralSecurityException("SunEC rejected the genuine signature");
            }
            System.out.println("JAVA-PROBE VERIFY_OK provider=" + verifier.getProvider().getName());

            stage = "sunec-tamper-refusal";
            byte[] tampered = message.clone();
            tampered[0] ^= 1;
            verifier.initVerify(independentPublic);
            verifier.update(tampered);
            if (verifier.verify(signature)) {
                throw new GeneralSecurityException("SunEC accepted the signature for changed message bytes");
            }
            System.out.println("JAVA-PROBE TAMPER_REJECTED");
        } catch (Exception | LinkageError failure) {
            result = setupComplete ? 1 : 2;
            failure(setupComplete ? "OPERATION_FAIL" : "SETUP_FAIL", stage, failure, pin);
        } finally {
            clearPasswords(passwords);
            if (token != null && loggedIn) {
                try {
                    token.logout();
                    System.out.println("JAVA-PROBE LOGOUT_OK");
                } catch (Exception | LinkageError failure) {
                    failure("CLEANUP_FAIL", "logout", failure, pin);
                    if (result == 0) {
                        result = 3;
                    }
                }
            } else {
                System.out.println("JAVA-PROBE LOGOUT_SKIPPED reason=no-successful-login");
            }
            Arrays.fill(pin, '\0');
        }
        if (result == 0) {
            System.out.println("JAVA-PROBE PASS");
        }
        System.exit(result);
    }

    private static void clearPasswords(List<PasswordCallback> passwords) {
        for (PasswordCallback password : passwords) {
            password.clearPassword();
        }
        passwords.clear();
    }

    private static void failure(String kind, String stage, Throwable failure, char[] pin) {
        System.err.println("JAVA-PROBE " + kind + " stage=" + stage);
        // Retain nested CKR diagnostics while keeping PIN text out of this probe's output.
        String secret = new String(pin);
        Throwable cause = failure;
        for (int depth = 0; cause != null && depth < 8; depth++) {
            String message = String.valueOf(cause.getMessage()).replace('\n', ' ').replace('\r', ' ');
            if (!secret.isEmpty()) {
                message = message.replace(secret, "[PIN]");
            }
            System.err.println("JAVA-PROBE cause=" + cause.getClass().getName() + " message=" + message);
            if (cause.getCause() == cause) {
                break;
            }
            cause = cause.getCause();
        }
    }
}
