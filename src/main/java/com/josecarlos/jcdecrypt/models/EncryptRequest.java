package com.josecarlos.jcdecrypt.models;

public class EncryptRequest {

    private Integer length;
    private String text;

    public Integer getLength() {
        return length;
    }

    public void setLength(Integer length) {
        this.length = length;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return "EncryptRequest{" +
                "length=" + length +
                ", text='" + text + '\'' +
                '}';
    }
}
