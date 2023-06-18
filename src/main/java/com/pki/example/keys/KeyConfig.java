package com.pki.example.keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.security.*;

@Configuration
public class KeyConfig {

    @Value("${security.key-store}")
    private String keyStorePath;

    @Value("${security.key-store-password}")
    private String keyStorePassword;

    @Value("${security.key-alias}")
    private String keyAlias;

    @Value("${security.key-password}")
    private String keyPassword;

    @Bean
    public Key encryptionKey() throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
        Key key = keystore.getKey(keyAlias, keyPassword.toCharArray());
        return key;
    }
    @Bean
    public Key secretKey() throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
        Key key = keystore.getKey("mykey", keyPassword.toCharArray());
        return key;
    }

    public KeyPair getKeyPairFromKeyStore() throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());

        Key privateKey = keystore.getKey(keyAlias, keyPassword.toCharArray());
        PublicKey publicKey = keystore.getCertificate(keyAlias).getPublicKey();

        return new KeyPair(publicKey, (PrivateKey) privateKey);
    }
}