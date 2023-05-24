package com.pki.example.dto;

import javax.validation.constraints.Pattern;

public class UpdateUserDTO {
    @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Has to be in the form of an email")
    public String username;
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
