package simplesso.sso.configuration;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import simplesso.sso.models.User;
import simplesso.sso.utils.JwkUtils;

import java.nio.file.Path;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    private final AuthorizationServerProperties authorizationServerProperties;

    public AuthorizationServerConfig(AuthorizationServerProperties authorizationServerProperties) {
        this.authorizationServerProperties = authorizationServerProperties;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.exceptionHandling(exceptions ->
                exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        );
        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(JwtProperties properties) throws Exception {
        ECPublicKey publicKey;
        ECPrivateKey privateKey;
        if (properties.isGenerateTemp()) {
            var pair = JwkUtils.generateECKeys();
            publicKey = (ECPublicKey) pair.getPublic();
            privateKey = (ECPrivateKey) pair.getPrivate();
        } else {
            publicKey = JwkUtils.readECPublicKey(Path.of(properties.getPublicKeyPath()));
            privateKey = JwkUtils.readECPrivateKey(Path.of(properties.getPrivateKeyPath()));
        }
        JWK jwk = JwkUtils.getEcKey(publicKey, privateKey);
        return (jwkSelector, securityContext) -> List.of(jwk);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oauth2AccessTokenCustomizer() {
        return (ctx) -> {
            if (ctx.getTokenType() == OAuth2TokenType.ACCESS_TOKEN) {
                User user = (User) ctx.getPrincipal().getPrincipal();
                List<String> roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
                ctx.getClaims().claims((map) -> {
                    map.put("userId", user.getId());
                    map.put("roles", roles);
                });
            }
            ctx.getJwsHeader().algorithm(SignatureAlgorithm.ES256);
        };
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(authorizationServerProperties.getIssuerUrl())
                .tokenIntrospectionEndpoint(authorizationServerProperties.getIntrospectionEndpoint())
                .build();
    }
}