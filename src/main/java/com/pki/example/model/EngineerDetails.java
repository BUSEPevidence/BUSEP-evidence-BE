package com.pki.example.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@Entity
@NoArgsConstructor
@Table(name = "engineers")
public class EngineerDetails {

    @Id
    @Column(name = "user_id")
    private int userId;

    private Seniority seniority;

    private String CvUrl;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    @MapsId
    private User user;

    public EngineerDetails(User user, Seniority seniority){
        this.user = user;
        this.seniority = seniority;
    }
}
