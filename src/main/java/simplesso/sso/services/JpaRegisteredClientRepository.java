package simplesso.sso.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import simplesso.sso.models.Client;
import simplesso.sso.repositories.ClientRepository;

@Slf4j
@Component
public class JpaRegisteredClientRepository implements RegisteredClientRepository {
    @Autowired
    private ClientRepository clientRepository;
    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException();
    }

    @Override
    public RegisteredClient findById(String id) {
        log.debug("RegisteredClient findById {}", id);
        return clientRepository.findById(id).map(Client::toRegisteredClient).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        log.debug("RegisteredClient findByClientId {}", clientId);
        return clientRepository.findByClientId(clientId).map(Client::toRegisteredClient).orElse(null);
    }
}
