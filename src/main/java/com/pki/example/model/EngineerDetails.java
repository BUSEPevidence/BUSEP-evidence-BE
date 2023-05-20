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

    @ManyToOne
    @JoinColumn(name = "user_id", insertable = false, updatable = false)
    private User user;

}
