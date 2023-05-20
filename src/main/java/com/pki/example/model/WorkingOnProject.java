package com.pki.example.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Date;

@Data
@Entity
@NoArgsConstructor
@Table(name = "worksonproject")
public class WorkingOnProject {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id", referencedColumnName = "id")
    private Project project;

    private Date startedWorking;

    private Date endedWorking;

    private String workDescription;

    private String experience;

    public WorkingOnProject(User user, Project project, Date startedWorking, Date endedWorking, String workDescription){
        this.user = user;
        this.project = project;
        this.startedWorking = startedWorking;
        this.endedWorking = endedWorking;
        this.workDescription = workDescription;
    }
}
