package com.pki.example.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import java.security.Permissions;
import java.util.ArrayList;
import java.util.List;

@Entity
@NoArgsConstructor
@Table(name="Role")
public class Role implements GrantedAuthority {

    private static final long serialVersionUID = 1L;
    
    @Id
    @Column(name="id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    int id;
    @Column(name="name")
    String name;
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "role_permission",
            joinColumns = @JoinColumn(name = "roleId", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "permissionId", referencedColumnName = "id"))
    private List<Permission> permissions;




    @JsonIgnore
    @Override
    public String getAuthority() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getName() {
        return name;
    }
    @JsonIgnore
    public int getId() {
        return id;
    }

    public void setId(int Id) {
        this.id = Id;
    }

    public List<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<Permission> permissions) {
        this.permissions = permissions;
    }

    public Role(String name, Permission permission) {
        this.name = name;
        this.permissions = new ArrayList<Permission>();
        this.permissions.add(permission);
    }
}
