package com.pki.example.model;


import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.apache.commons.lang3.RandomStringUtils;

import javax.persistence.*;
import java.util.Collection;
import java.util.List;

@Data
@Entity
@NoArgsConstructor
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String username;

    private String password;

    private String firstname;

    private String lastname;

    private String address;

    private String city;

    private String state;

    private String number;

    private String title;

    private String salt;

    private boolean adminApprove;

    private String activationCode;


    public User(String username, String password, String firstname, String lastname, String address, String city, String state, String number, String title, String salt, boolean adminApprove) {
        this.activationCode = RandomStringUtils.randomAlphanumeric(32);
        this.username = username;
        this.password = password;
        this.firstname = firstname;
        this.lastname = lastname;
        this.address = address;
        this.city = city;
        this.state = state;
        this.number = number;
        this.title = title;
        this.salt = salt;
        this.adminApprove = adminApprove;
    }


//    @Enumerated(EnumType.STRING)
//    private Role role;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("role.name()"));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
