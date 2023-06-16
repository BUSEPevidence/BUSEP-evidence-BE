package com.pki.example.model;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class UploadResult {
    private String key;
    private String blobName;

    public UploadResult(String key, String blobName) {
        this.key = key;
        this.blobName = blobName;
    }

    public String getKey() {
        return key;
    }

    public String getBlobName() {
        return blobName;
    }
}
