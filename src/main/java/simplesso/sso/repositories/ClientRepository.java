package simplesso.sso.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import simplesso.sso.models.Client;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, String> {
    Optional<Client> findByClientId(String clientId);
}
