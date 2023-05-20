package com.pki.example.uploader;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import javax.annotation.PostConstruct;
import java.io.IOException;

@Configuration
public class FirebaseInitializer {
    @PostConstruct
    public void initialize() throws IOException {
        FirebaseOptions options = FirebaseOptions.builder()
                .setCredentials(GoogleCredentials.fromStream(new ClassPathResource("../resources/busepdb-firebase-adminsdk-zz9go-dcfcfe419b.json").getInputStream()))
                .setStorageBucket("gs://busepdb.appspot.com")
                .build();
        FirebaseApp.initializeApp(options);
    }
}
