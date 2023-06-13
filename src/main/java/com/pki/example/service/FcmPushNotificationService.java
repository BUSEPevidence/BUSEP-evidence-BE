package com.pki.example.service;

import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingException;
import com.google.firebase.messaging.Message;
import org.springframework.stereotype.Service;

@Service
public class FcmPushNotificationService {

    public void sendNotification(String message) {
        // Create FCM message
        Message fcmMessage = Message.builder()
                .putData("message", message)
                .setTopic("notifications") // Topic to which the message will be sent
                .build();

        // Send FCM message
        try {
            FirebaseMessaging.getInstance().send(fcmMessage);
        } catch (FirebaseMessagingException e) {
            // Handle exception
            e.printStackTrace();
        }
    }
}