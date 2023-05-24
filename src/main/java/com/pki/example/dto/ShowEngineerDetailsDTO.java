package com.pki.example.dto;

import com.pki.example.model.Seniority;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class ShowEngineerDetailsDTO {

    public Seniority seniority;

    public String CvUrl;
}
