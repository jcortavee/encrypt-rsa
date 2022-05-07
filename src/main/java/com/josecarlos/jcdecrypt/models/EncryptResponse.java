package com.josecarlos.jcdecrypt.models;

public class EncryptResponse {

    private String encrypt;

    public EncryptResponse() {
    }

    public EncryptResponse(String encrypt) {
        this.encrypt = encrypt;
    }

    public String getEncrypt() {
        return encrypt;
    }

    public void setEncrypt(String encrypt) {
        this.encrypt = encrypt;
    }
}
