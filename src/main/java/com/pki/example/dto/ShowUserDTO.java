package com.pki.example.dto;

import com.pki.example.model.Role;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;

import java.util.List;

@RequiredArgsConstructor
@AllArgsConstructor
public class ShowUserDTO {
    public String username;

    public String firstname;

    public String lastname;

    public String address;

    public String city;

    public String state;

    public String number;

    public List<Role> roles;
}
