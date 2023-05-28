package com.pki.example.dto;

import javax.validation.constraints.Pattern;

public class UpdateUserDTO {
    @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Has to be in the form of an email")
    public String username;
    public String firstname;
    public String lastname;
    public String address;
    public String city;
    public String state;
    public String number;
}
