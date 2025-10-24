package com.example.bsep_team25.service;

import com.example.bsep_team25.dto.RecaptchaResponse;
import com.example.bsep_team25.iservice.ICaptchaService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class CaptchaService implements ICaptchaService {

    @Value("${recaptcha.secret.key}")
    private String secretKey;

    @Value("${recaptcha.verify.url}")
    private String verifyUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public boolean validateCaptcha(String captchaToken, String ipAddress) {
        if (captchaToken == null || captchaToken.trim().isEmpty()) {
            System.out.println("❌ CAPTCHA token is missing");
            return false;
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("secret", secretKey);
            requestBody.add("response", captchaToken);
            requestBody.add("remoteip", ipAddress);

            HttpEntity<MultiValueMap<String, String>> requestEntity =
                    new HttpEntity<>(requestBody, headers);

            ResponseEntity<RecaptchaResponse> response = restTemplate.postForEntity(
                    verifyUrl,
                    requestEntity,
                    RecaptchaResponse.class
            );

            RecaptchaResponse recaptchaResponse = response.getBody();

            if (recaptchaResponse == null || !recaptchaResponse.isSuccess()) {
                System.out.println("❌ CAPTCHA failed for IP: " + ipAddress);
                return false;
            }

            System.out.println("✅ CAPTCHA passed for IP: " + ipAddress);
            return true;

        } catch (Exception e) {
            System.out.println("⚠️ Error verifying reCAPTCHA: " + e.getMessage());
            return false;
        }
    }
}
