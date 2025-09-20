package com.example.bsep_team25.util;

import java.util.Arrays;
import java.util.List;

public class PasswordValidator {

    private static final List<String> COMMON_PASSWORDS = Arrays.asList(
            "password", "123456", "123456789", "qwerty", "12345678",
            "111111", "123123", "abc123", "password1", "1234567"
    );

    public static boolean isValid(String password) {
        if (password == null) return false;

        int len = password.length();

        // 1. Dužina
        if (len < 8 || len > 64) return false;

        // 2. Da nije samo whitespace
        if (password.trim().isEmpty()) return false;

        // 3. Da nije u listi "poznatih slabih lozinki"
        String lower = password.toLowerCase();
        if (COMMON_PASSWORDS.contains(lower)) return false;

        return true;
    }

}
