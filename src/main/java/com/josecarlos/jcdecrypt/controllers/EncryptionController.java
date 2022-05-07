package com.josecarlos.jcdecrypt.controllers;

import com.josecarlos.jcdecrypt.models.DecryptResponse;
import com.josecarlos.jcdecrypt.models.EncryptRequest;
import com.josecarlos.jcdecrypt.models.EncryptResponse;
import com.josecarlos.jcdecrypt.services.RSAService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@RestController
public class EncryptionController {

    private final RSAService rsaService;

    public EncryptionController(RSAService rsaService) {
        this.rsaService = rsaService;
    }


    @PostMapping("/encrypt")
    public ResponseEntity<EncryptResponse> encrypt(@RequestBody EncryptRequest request) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        System.out.println(request);
        String value = rsaService.encrypt(request);
//        String encrypted = AESEncryptService.encrypt(request.getTexto(), request.getSeed());
        EncryptResponse response = new EncryptResponse(value);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<DecryptResponse> decrypt(@RequestBody EncryptRequest request) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException, InvalidKeySpecException {
        String encrypted = rsaService.decrypt(request);
        DecryptResponse response = new DecryptResponse(encrypted);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

}
