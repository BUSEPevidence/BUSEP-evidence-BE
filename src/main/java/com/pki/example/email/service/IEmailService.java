package com.pki.example.email.service;

import com.pki.example.email.model.EmailDetails;
import org.springframework.scheduling.annotation.Async;

public interface IEmailService {

    void sendWelcomeMail(EmailDetails details);
}
