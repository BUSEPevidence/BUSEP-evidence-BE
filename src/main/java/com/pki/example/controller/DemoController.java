package com.pki.example.controller;

import com.pki.example.keys.KeyConfig;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Date;

import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Decode;
import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Encode;

@RestController
@RequestMapping("/api/demo")
public class DemoController {

    @Autowired
    KeyConfig keyConfig;

    @Value("${custom.nameKey}")
    String nameKey;

    @GetMapping("/roless")
    public ResponseEntity<String> sayHello()
    {
        Date specificDate = new Date(2023 - 1900, 4, 17);
        System.out.println(specificDate);
        Date specificDatee = new Date(2023, 4, 17);
        System.out.println(specificDatee);
        return ResponseEntity.ok("Hello man with valid token");
    }
    @GetMapping("/role")
    @PreAuthorize("hasAuthority('CREATE_HI')")
    public ResponseEntity<String> sayHi()
    {
        return ResponseEntity.ok("Hi man with User role");
    }


    public static SecretKey generateAESKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeySpecException {
        // Generate a SecretKey from the password using PBKDF2 key derivation function
        byte[] salt = "someSalt".getBytes(StandardCharsets.UTF_8);
        int iterationCount = 10000;
        int keyLength = 256;

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        // Convert the derived key to an AES key
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    @SneakyThrows
    @GetMapping("/keys")
    public ResponseEntity<String> ShowKeys()
    {
       String keyString = nameKey;
       String message = "Batonga";
       byte[] bytes = keyString.getBytes(StandardCharsets.UTF_8);
       Key secretKey = new SecretKeySpec(bytes, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] EncryptedString = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        String encryptedStringg = base64Encode(EncryptedString);
        System.out.println(encryptedStringg);

        byte[] decodedBytes = base64Decode("uoWCDzBPLDdbyYa0w3q9mg==");
        Cipher cipherr = Cipher.getInstance("AES");
        cipherr.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipherr.doFinal(decodedBytes);
        String decryptedString = new String(decryptedBytes);
        System.out.println(decryptedString);






        return ResponseEntity.ok("dzi dzi");
    }

    @SneakyThrows
    @GetMapping("/save")
    public void SaveToKeyStore()
    {
        try {
            // Učitajte postojeći keystore iz datoteke
            FileInputStream fis = new FileInputStream("src/main/resources/keys/key.jks");
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(fis, "password".toCharArray());
            fis.close();

            // Generišite AES ključ
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256); // Postavite željenu dužinu ključa (u ovom primeru 256 bita)
            SecretKey secretKey = keyGenerator.generateKey();

            // Sačuvajte AES ključ u keystore
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.ProtectionParameter keyPassword = new KeyStore.PasswordProtection("password".toCharArray());
            keyStore.setEntry("mykey", secretKeyEntry, keyPassword);

            // Sačuvajte izmenjeni keystore nazad u datoteku
            FileOutputStream fos = new FileOutputStream("src/main/resources/keys/key.jks");
            keyStore.store(fos, "password".toCharArray());
            fos.close();

            System.out.println("AES ključ je uspešno dodat u keystore.");

        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException e) {
            e.printStackTrace();
        }
    }
}