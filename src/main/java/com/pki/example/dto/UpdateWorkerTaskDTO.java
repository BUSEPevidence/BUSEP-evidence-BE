package com.pki.example.dto;

import javax.validation.constraints.Pattern;

public class UpdateWorkerTaskDTO {
    @Pattern(regexp = "^[0-9]+$", message = "Id must be numbers only")
    public int projectId;
    public String task;
}
