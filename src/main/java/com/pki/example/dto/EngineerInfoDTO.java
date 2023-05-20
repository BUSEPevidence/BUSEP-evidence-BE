package com.pki.example.dto;

import com.pki.example.model.EngineerDetails;
import com.pki.example.model.Experience;
import com.pki.example.model.User;

import java.util.List;

public class EngineerInfoDTO {

    public User user;
    public List<Experience> experiences;
    public EngineerDetails details;

    public EngineerInfoDTO(User user, List<Experience> experiences, EngineerDetails details){
        this.user = user;
        this.experiences = experiences;
        this.details = details;
    }
}
