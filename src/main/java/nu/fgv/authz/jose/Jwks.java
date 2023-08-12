package nu.fgv.authz.jose;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

public final class Jwks {

    private Jwks() {
    }

    public static RSAKey generateRsa() {
        final KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    public static ECKey generateEc() {
        final KeyPair keyPair = KeyGeneratorUtils.generateEcKey();
        final ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        final ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        final Curve curve = Curve.forECParameterSpec(publicKey.getParams());

        return new ECKey.Builder(curve, publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    public static OctetSequenceKey generateSecret() {
        final SecretKey secretKey = KeyGeneratorUtils.generateSecretKey();

        return new OctetSequenceKey.Builder(secretKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

}
