package simplesso.sso.services;

import org.springframework.stereotype.Service;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class JwtKeyHolderService {
    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;

    public JwtKeyHolderService(ECPrivateKey privateKey, ECPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public ECPrivateKey getPrivateKey() {
        return privateKey;
    }

    public ECPublicKey getPublicKey() {
        return publicKey;
    }
}
