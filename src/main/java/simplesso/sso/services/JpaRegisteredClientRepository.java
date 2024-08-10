package simplesso.sso.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import simplesso.sso.models.Client;
import simplesso.sso.repositories.ClientRepository;

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
        return clientRepository.findById(id).map(Client::toRegisteredClient).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId).map(Client::toRegisteredClient).orElse(null);
    }
}
