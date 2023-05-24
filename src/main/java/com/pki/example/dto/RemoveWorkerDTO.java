package com.pki.example.dto;

import javax.validation.constraints.Pattern;

public class RemoveWorkerDTO {
    @Pattern(regexp = "^[0-9]+$", message = "Id must be numbers only")
    public int projectId;
    @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Has to be in the form of an email")
    public String username;
}
