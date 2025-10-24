package com.example.bsep_team25.iservice;

public interface ICaptchaService {
    boolean validateCaptcha(String captchaToken, String ipAddress);
}
