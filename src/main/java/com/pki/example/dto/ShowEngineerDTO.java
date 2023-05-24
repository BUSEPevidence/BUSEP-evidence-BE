package com.pki.example.dto;

import lombok.AllArgsConstructor;

import java.util.List;
@AllArgsConstructor
public class ShowEngineerDTO {
    public ShowUserDTO user;

    public List<ShowExperienceDTO> experiences;

    public ShowEngineerDetailsDTO details;
}
