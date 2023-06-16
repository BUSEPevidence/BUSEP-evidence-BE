package com.pki.example.uploader;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.*;
import com.pki.example.model.UploadResult;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;

@Service
public class FileUploadService {
    private static final String KEYSTORE_PASSWORD = "password";
    private static final String KEY_ALIAS = "mycaserver3";
    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String BUCKET_NAME = "busepdb.appspot.com";

    public UploadResult uploadFile(MultipartFile file) throws Exception {
        System.out.println("Uploadovao");
        // Generate the secret key
        SecretKey secretKey = generateSecretKey();

        // Encrypt the file
        byte[] encryptedData = encrypt(file.getInputStream(), secretKey);

        // Upload the encrypted file to cloud storage
        BlobId blobId = BlobId.of(BUCKET_NAME, "encrypted_" + Objects.requireNonNull(file.getOriginalFilename()));
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId).build();

        StorageOptions options = StorageOptions.newBuilder()
                .setCredentials(GoogleCredentials.fromStream(new ClassPathResource("busepdb-firebase-adminsdk-zz9go-b90fec76a6.json").getInputStream()))
                .build();
        Storage storage = options.getService();

        Blob blob = storage.create(blobInfo, encryptedData);

        // Encrypt the AES secret key with RSA HERE IS THE PROBLEM
        byte[] encryptedKey = encryptRSA(secretKey.getEncoded(), getRSAPublicKey());
        String encodedEncryptedKey = Base64.getEncoder().encodeToString(encryptedKey);

        System.out.println("OVO:" + encodedEncryptedKey + "|" + blob.getName());
        return new UploadResult(encodedEncryptedKey, blob.getName());
    }

    public void downloadFiles(String blobName, String encKey) throws Exception {
        StorageOptions options = StorageOptions.newBuilder()
                .setCredentials(GoogleCredentials.fromStream(new ClassPathResource("busepdb-firebase-adminsdk-zz9go-b90fec76a6.json").getInputStream()))
                .build();
        Storage storage = options.getService();

        Blob blob = storage.get(BUCKET_NAME, blobName);
        if (blob == null) {
            throw new RuntimeException("Blob not found");
        }

        // Download the encrypted file
        byte[] encryptedData = blob.getContent(Blob.BlobSourceOption.generationMatch());

        // Decode the base64-encoded encrypted AES key
        byte[] encryptedKey = Base64.getDecoder().decode(encKey);

        // Decrypt the AES key with RSA private key
        SecretKey secretKey = decryptRSA(encryptedKey, getRSAPrivateKey());

        // Decrypt the file with the AES key
        byte[] decryptedData = decrypt(encryptedData, secretKey);

        // Save the decrypted file
        Path savePath = Path.of("src/main/resources/Cv.pdf");
        try (InputStream inputStream = new ByteArrayInputStream(decryptedData)) {
            Files.write(savePath, decryptedData, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Thread.sleep(2000);
        }
    }

    private SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGenerator.init(256); // Key size of 256 bits
        return keyGenerator.generateKey();
    }

    private byte[] encrypt(InputStream inputStream, SecretKey secretKey) throws Exception {
        byte[] inputData = inputStream.readAllBytes();
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(inputData);
    }

    private byte[] decrypt(byte[] cipherText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(cipherText);
    }

    public PublicKey getRSAPublicKey() throws Exception {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");

            // Load the keystore file from the classpath
            InputStream inputStream = getClass().getClassLoader().getResourceAsStream("static/httpsKS.jks");
            keyStore.load(inputStream, KEYSTORE_PASSWORD.toCharArray());

            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);

            return certificate.getPublicKey();
        } catch (Exception e) {
            e.printStackTrace();
            throw e; // or handle the exception accordingly
        }
    }

    public PrivateKey getRSAPrivateKey() throws Exception {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream inputStream = getClass().getClassLoader().getResourceAsStream("static/httpsKS.jks");
            keyStore.load(inputStream, KEYSTORE_PASSWORD.toCharArray());

            Key key = keyStore.getKey(KEY_ALIAS, KEYSTORE_PASSWORD.toCharArray());
            return (PrivateKey) key;
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    private byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private SecretKey decryptRSA(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKey, AES_ALGORITHM);
    }
  /*
    public void downloadFiles(String blobName) throws IOException {
        Storage storage = StorageClient.getInstance().bucket().getStorage();
        Blob blob = storage.get("busepdb.appspot.com", blobName);

        if (blob == null) {
            throw new RuntimeException("Blob not found");
        }

        ReadableByteChannel channel = blob.reader();
        InputStream inputStream = Channels.newInputStream(channel);

        Path savePath = Path.of("src/main/resources/Cv.pdf");
        Files.copy(inputStream, savePath, StandardCopyOption.REPLACE_EXISTING);
    } download bez enkripcije*/
}
