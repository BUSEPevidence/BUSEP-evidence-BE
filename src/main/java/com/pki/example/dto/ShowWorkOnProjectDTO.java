package com.pki.example.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.pki.example.model.Project;
import lombok.AllArgsConstructor;

import java.util.Date;
@AllArgsConstructor
public class ShowWorkOnProjectDTO {
    public int id;

    @JsonIgnoreProperties({"hibernateLazyInitializer"})
    public Project project;
    public Date startedWorking;

    public Date endedWorking;

    public String workDescription;

    public String experience;
}
