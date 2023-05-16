package com.pki.example.email.service;

import com.pki.example.email.model.EmailDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.mail.internet.MimeMessage;

@Service
public class EmailService implements IEmailService {

    @Autowired
    private JavaMailSender javaMailSender;

    @Value
            ("${spring.mail.username}") private String sender;

    @Async
    @Override
    public void sendWelcomeMail(EmailDetails details)
    {
        try {
            MimeMessage mailMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mailMessage, "utf-8");
            helper.setFrom(sender);
            helper.setTo(details.getRecipient());
            helper.setText(details.getMsgBody(), true);
            helper.setSubject(details.getSubject());
            javaMailSender.send(mailMessage);
        }
        catch (Exception ignored) {
        }
    }
}
