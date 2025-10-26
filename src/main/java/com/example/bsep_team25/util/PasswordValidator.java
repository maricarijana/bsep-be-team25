package com.example.bsep_team25.util;

import java.security.SecureRandom;
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

    // ==================== PASSWORD GENERATOR ====================

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    private static final String ALL_CHARS = UPPERCASE + LOWERCASE + DIGITS + SPECIAL;
    private static final SecureRandom random = new SecureRandom();

    public static String generateSecurePassword() {
        int length = 16;
        StringBuilder password = new StringBuilder(length);

        password.append(UPPERCASE.charAt(random.nextInt(UPPERCASE.length())));
        password.append(LOWERCASE.charAt(random.nextInt(LOWERCASE.length())));
        password.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
        password.append(SPECIAL.charAt(random.nextInt(SPECIAL.length())));

        for (int i = 4; i < length; i++) {
            password.append(ALL_CHARS.charAt(random.nextInt(ALL_CHARS.length())));
        }

        return shuffleString(password.toString());
    }

    private static String shuffleString(String input) {
        char[] characters = input.toCharArray();
        for (int i = characters.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = characters[i];
            characters[i] = characters[j];
            characters[j] = temp;
        }
        return new String(characters);
    }
}

