package org.penpal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class EmailSendingRunner {
    public static void main(String []args) {
        SpringApplication.run(EmailSendingRunner.class,args);
    }

    @Bean(name = "emailSendingRestTemplate")
    public RestTemplate restTemplate(){
        return new RestTemplate();
    }
}