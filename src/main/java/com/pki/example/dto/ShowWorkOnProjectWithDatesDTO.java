package com.pki.example.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.pki.example.model.Project;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;

import java.util.Date;
import java.util.List;
@RequiredArgsConstructor
@AllArgsConstructor
public class ShowWorkOnProjectWithDatesDTO {
    public String username;

    public String firstname;

    public String lastname;

    public String address;

    public String city;

    public String state;

    public String number;

    public List<String> roles;

    public Date startedWorking;

    public Date endedWorking;
}
