package com.pki.example.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@Entity
@NoArgsConstructor
@Table(name = "admins")
public class AdminLogins {
    @Id
    @Column(name = "user_id")
    private int userId;

    private Boolean changedPassword;

    @ManyToOne
    @JoinColumn(name = "user_id", insertable = false, updatable = false)
    private User user;

    public AdminLogins(User user, Boolean flag){
        this.user = user;
        this.changedPassword = flag;
    }
}
