package com.josecarlos.jcdecrypt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
public class JcDecryptApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplication.run(JcDecryptApplication.class, args);
    }

}
