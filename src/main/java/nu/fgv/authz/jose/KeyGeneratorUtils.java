package nu.fgv.authz.jose;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

class KeyGeneratorUtils {

    private KeyGeneratorUtils() {
    }

    static SecretKey generateSecretKey() {
        final SecretKey hmacKey;

        try {
            hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return hmacKey;
    }

    static KeyPair generateRsaKey() {
        final KeyPair keyPair;

        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
        return keyPair;
    }

    static KeyPair generateEcKey() {
        final EllipticCurve ellipticCurve = new EllipticCurve(
                new ECFieldFp(
                        new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")
                ),
                new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
                new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291")
        );
        final ECPoint ecPoint = new ECPoint(
                new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
                new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109")
        );
        final ECParameterSpec ecParameterSpec = new ECParameterSpec(
                ellipticCurve,
                ecPoint,
                new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
                1
        );
        final KeyPair keyPair;

        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");

            keyPairGenerator.initialize(ecParameterSpec);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
        return keyPair;
    }
}
