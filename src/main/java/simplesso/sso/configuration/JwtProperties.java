package simplesso.sso.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("jwt")
public class JwtProperties {
    private boolean generateTemp;
    private String publicKeyPath;
    private String privateKeyPath;

    public JwtProperties() {
    }

    public String getPublicKeyPath() {
        return publicKeyPath;
    }

    public void setPublicKeyPath(String publicKeyPath) {
        this.publicKeyPath = publicKeyPath;
    }

    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }

    public boolean isGenerateTemp() {
        return generateTemp;
    }

    public void setGenerateTemp(boolean generateTemp) {
        this.generateTemp = generateTemp;
    }
}
