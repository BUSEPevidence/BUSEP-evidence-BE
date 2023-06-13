package com.pki.example.service;

import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingException;
import com.google.firebase.messaging.Message;
import com.pki.example.email.model.EmailDetails;
import com.pki.example.email.service.EmailService;
import com.pki.example.email.service.IEmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AlertService {

    @Autowired
    private FcmPushNotificationService fcmPushNotificationService;

    @Autowired
    private IEmailService emailService;

    public void sendPushNotification(String message) {
        // Log critical event
        // ...

        // Send push notification
        fcmPushNotificationService.sendNotification(message);
    }

    public void sendEmailNotification(String message, String username) {
        // Log critical event
        // ...

        // Send e-mail notification
        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setMsgBody("Critical log!<br/>" +
                "" + message +"</h2> <br/>");
        emailDetails.setSubject("Welcome email");
        emailDetails.setRecipient(username);
        emailService.sendWelcomeMail(emailDetails);
    }
}

