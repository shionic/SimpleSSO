package simplesso.sso.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import simplesso.sso.models.UserRole;

public interface UserRoleRepository extends JpaRepository<UserRole, Long> {
}
