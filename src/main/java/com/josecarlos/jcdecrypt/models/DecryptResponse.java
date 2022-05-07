package com.josecarlos.jcdecrypt.models;

public class DecryptResponse {

    private String decrypt;

    public DecryptResponse() {
    }

    public DecryptResponse(String decrypt) {
        this.decrypt = decrypt;
    }

    public String getDecrypt() {
        return decrypt;
    }

    public void setDecrypt(String decrypt) {
        this.decrypt = decrypt;
    }
}
