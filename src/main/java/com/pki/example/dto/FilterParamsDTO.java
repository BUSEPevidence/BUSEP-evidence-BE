package com.pki.example.dto;

import lombok.AllArgsConstructor;

import java.sql.Date;

@AllArgsConstructor
public class FilterParamsDTO {
    public String firstname;

    public String surname;

    public String email;

    public Date workDate;
}
