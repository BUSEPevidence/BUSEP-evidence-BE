package com.pki.example.uploader;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Objects;

@Service
public class FileUploadService {
    private static final String BUCKET_NAME = "gs://busepdb.appspot.com";

    public String uploadFile(MultipartFile file) throws IOException {
        BlobId blobId = BlobId.of(BUCKET_NAME, Objects.requireNonNull(file.getOriginalFilename()));
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId).build();

        StorageOptions options = StorageOptions.newBuilder()
                .setCredentials(GoogleCredentials.fromStream(new ClassPathResource("../resources/busepdb-firebase-adminsdk-zz9go-dcfcfe419b.json").getInputStream()))
                .build();
        Storage storage = options.getService();

        Blob blob = storage.create(blobInfo, file.getBytes());
        return blob.getMediaLink();
    }
}
