package com.pki.example.notifications;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;

@Controller
@CrossOrigin(maxAge = 3600)
public class MessageController {


    @SendTo("/topic/notification")
    public String sendNotification(String notification){
        return notification;
    }

    @SendTo("/logger/logg")
    public String sendLogg(String logg){
        return logg;
    }



}
