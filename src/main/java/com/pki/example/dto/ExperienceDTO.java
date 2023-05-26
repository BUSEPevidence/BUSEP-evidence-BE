package com.pki.example.dto;

import javax.validation.constraints.Pattern;

public class ExperienceDTO {

    public String title;
    @Pattern(regexp = "^[0-5]$", message = "Grade must be numbers only")
    public int grade;
}
