package simplesso.sso.utils;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;

public class JwkUtils {

    public static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    public static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    public static KeyPair generateEd25519Keys() {
        KeyPair pair;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");

            keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());

            pair = keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new SecurityException(e);
        }
        return  pair;
    }

    public static ECKey generateEc() {
        KeyPair pair = generateEd25519Keys();
        return new ECKey.Builder(Curve.P_256, (ECPublicKey) pair.getPublic())
                .privateKey(pair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }
}

