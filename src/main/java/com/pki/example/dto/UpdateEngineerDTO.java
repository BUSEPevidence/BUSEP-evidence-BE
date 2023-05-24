package com.pki.example.dto;

import javax.validation.constraints.Pattern;

public class UpdateEngineerDTO {
    @Pattern(regexp = "^(?=.*\\d)(?=.*[a-zA-Z]).{8,}$", message = "Password must be at least 8 characters long and contain both letters and numbers")
    public String password;
    public String firstname;
    public String lastname;
    public String address;
    public String city;
    public String state;
    public String number;
    public String title;
}
