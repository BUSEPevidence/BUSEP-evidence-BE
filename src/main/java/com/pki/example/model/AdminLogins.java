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

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    @MapsId
    private User user;

    public AdminLogins(User user, Boolean flag){
        this.user = user;
        this.changedPassword = flag;
    }
    public AdminLogins(Boolean flag){
        this.changedPassword = flag;
    }

    public int getUserId() {
        return userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public Boolean getChangedPassword() {
        return changedPassword;
    }

    public void setChangedPassword(Boolean changedPassword) {
        this.changedPassword = changedPassword;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
