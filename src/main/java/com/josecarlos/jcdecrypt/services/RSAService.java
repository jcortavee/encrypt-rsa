package com.josecarlos.jcdecrypt.services;

import com.josecarlos.jcdecrypt.models.EncryptRequest;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

@Service
public class RSAService {

    public String encrypt(EncryptRequest request) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (request.getLength() == 512 || request.getLength() == 1024 || request.getLength() == 2048 ||
                request.getLength() == 4096) {

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(request.getLength());
            KeyPair pair = generator.generateKeyPair();

            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();

            System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

            try (FileOutputStream fos = new FileOutputStream("public.key");
                 FileOutputStream fos2 = new FileOutputStream("private.key")) {
                fos.write(publicKey.getEncoded());
                fos2.write(privateKey.getEncoded());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] secretMessageBytes = request.getText().getBytes(StandardCharsets.UTF_8);
            byte[] encryptedMessageBytes = cipher.doFinal(secretMessageBytes);

            return Base64.getEncoder().encodeToString(encryptedMessageBytes);
        }

        throw new RuntimeException("The length has an invalid number");
    }

    public String decrypt(EncryptRequest request) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {

        File privateKeyFile = new File("private.key");
        byte[] publicKeyBytes = Files.readAllBytes(privateKeyFile.toPath());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec publicKeySpec = new PKCS8EncodedKeySpec(publicKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(publicKeySpec);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decryptedMessageBytes = cipher.doFinal(Base64.getDecoder().decode(request.getText()));

        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);

    }

}
