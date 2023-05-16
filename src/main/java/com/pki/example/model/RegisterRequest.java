package com.pki.example.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String username;

    private String password;

    private String firstname;

    private String lastname;

    private String address;

    private String city;

    private String state;

    private String number;

    private String title;

    private String salt;

    private boolean adminApprove;
}
