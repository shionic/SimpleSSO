package simplesso.sso.utils;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
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

    public static KeyPair generateECKeys() {
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

    public static ECPrivateKey readECPrivateKey(Path path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        var bytes = new String(Files.readAllBytes(path))
                .replaceAll("\\r\\n", "")
                .replaceAll("\\n", "")
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "");
        return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(bytes)));
    }

    public static ECPublicKey readECPublicKey(Path path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        var bytes = new String(Files.readAllBytes(path))
                .replaceAll("\\r\\n", "")
                .replaceAll("\\n", "")
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(bytes));
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
    }

    public static ECKey getEcKey(ECPublicKey publicKey, ECPrivateKey privateKey) {
        return new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }
}

