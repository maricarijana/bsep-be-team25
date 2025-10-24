package com.example.bsep_team25.iservice;

public interface IPasswordResetTokenService {
    void createPasswordResetToken(String email);
    boolean resetPassword(String token, String newPassword);
}
