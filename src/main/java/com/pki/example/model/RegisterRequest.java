package com.pki.example.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import javax.validation.constraints.Pattern;


import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Has to be in the form of an email")
    private String username;

    @Pattern(regexp = "^(?=.*\\d)(?=.*[a-zA-Z]).{8,}$", message = "Password must be at least 8 characters long and contain both letters and numbers")
    private String password;

    private String firstname;

    private String lastname;

    private String address;

    private String city;

    private String state;

    private String number;

    private List<String> title;

    private boolean adminApprove;
}
