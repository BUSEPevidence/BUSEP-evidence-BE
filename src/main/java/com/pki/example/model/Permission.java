package com.pki.example.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;

@Entity
@Table(name="Permission")
public class Permission implements GrantedAuthority {
    private static final long serialVersionUID = 1L;

    @javax.persistence.Id
    @Column(name="id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long Id;
    @Column(name="name")
    String name;
    @JsonIgnore
    @Override
    public String getAuthority() {
        return name;
    }

    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
