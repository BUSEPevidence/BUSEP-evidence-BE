package com.pki.example.uploader;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.*;
import com.google.firebase.cloud.StorageClient;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Service
public class FileUploadService {
    private static final String BUCKET_NAME = "busepdb.appspot.com";

    public String uploadFile(MultipartFile file) throws IOException {
        BlobId blobId = BlobId.of(BUCKET_NAME, Objects.requireNonNull(file.getOriginalFilename()));
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId).build();

        StorageOptions options = StorageOptions.newBuilder()
                .setCredentials(GoogleCredentials.fromStream(new ClassPathResource("busepdb-firebase-adminsdk-zz9go-b90fec76a6.json").getInputStream()))
                .build();
        Storage storage = options.getService();

        Blob blob = storage.create(blobInfo, file.getBytes());
        return blob.getName();
    }

    public String downloadFile(String blobName){
        Storage storage = StorageClient.getInstance().bucket().getStorage();
        Blob blob = storage.get("busepdb.appspot.com", blobName);

        if (blob == null) {
            new Error("something went wrong");
        }
        String signedUrl = blob.signUrl(24, TimeUnit.HOURS).toString();
        return signedUrl;
    }
}
