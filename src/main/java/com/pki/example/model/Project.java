package com.pki.example.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.sql.Date;

@Data
@Entity
@NoArgsConstructor
@Table(name = "projects")
public class Project {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String title;
    private String description;
    private Date startTime;
    private Date endTime;

    public Project (String title, String description, Date start, Date end){
        this.title = title;
        this.description = description;
        this.startTime = start;
        this.endTime = end;
    }
}
