package simplesso.sso.models;

import jakarta.persistence.*;

@Entity(name = "UserRole")
@Table(name = "user_roles")
public class UserRole {
    @Id
    @SequenceGenerator(name = "user_roles_gen", sequenceName = "user_roles_seq", allocationSize = 1)
    @Column(name = "id", nullable = false, length = 64)
    private String id;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
