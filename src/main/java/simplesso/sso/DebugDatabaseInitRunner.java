package simplesso.sso;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import simplesso.sso.models.Client;
import simplesso.sso.models.User;
import simplesso.sso.models.UserRole;
import simplesso.sso.repositories.ClientRepository;
import simplesso.sso.repositories.UserRepository;
import simplesso.sso.repositories.UserRoleRepository;

import java.util.List;

@Component
public class DebugDatabaseInitRunner implements CommandLineRunner {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserRoleRepository userRoleRepository;
    @Autowired
    private ClientRepository clientRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Override
    public void run(String... args) throws Exception {
        if(args.length == 0 || !args[0].equals("--startup")) {
            return;
        }
        UserRole adminRole = new UserRole();
        adminRole.setId("ADMIN");
        adminRole = userRoleRepository.save(adminRole);
        User user = new User();
        user.setUsername("admin");
        user.setPassword(passwordEncoder.encode("admin"));
        user.setRoles(List.of(adminRole));
        userRepository.save(user);
        Client client = new Client();
        client.setId("test-client-id");
        client.setClientId("test-client");
        client.setClientSecret(passwordEncoder.encode("test-client"));
        client.setClientName("Test Client");
        client.setRedirectUri("http://localhost:5000/code");
        clientRepository.save(client);
    }
}
