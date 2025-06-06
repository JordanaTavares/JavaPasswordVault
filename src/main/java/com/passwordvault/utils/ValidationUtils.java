package com.passwordvault.utils;

import java.util.regex.Pattern;

public class ValidationUtils {
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[A-Za-z0-9+_.-]+@(.+)$"
    );

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
        "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$"
    );

    public static boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    public static boolean isValidPassword(String password) {
        return password != null && PASSWORD_PATTERN.matcher(password).matches();
    }

    public static String validateEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return "O email não pode estar vazio";
        }
        if (!isValidEmail(email)) {
            return "Formato de email inválido";
        }
        return null;
    }

    public static String validatePassword(String password) {
        if (password == null || password.trim().isEmpty()) {
            return "A senha não pode estar vazia";
        }
        if (!isValidPassword(password)) {
            return "A senha deve conter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais";
        }
        return null;
    }

    public static String validateService(String service) {
        if (service == null || service.trim().isEmpty()) {
            return "O nome do serviço não pode estar vazio";
        }
        if (service.length() < 3) {
            return "O nome do serviço deve ter pelo menos 3 caracteres";
        }
        return null;
    }

    public static String validate2FACode(String code) {
        if (code == null || code.trim().isEmpty()) {
            return "O código 2FA não pode estar vazio";
        }
        if (!code.matches("\\d{6}")) {
            return "O código 2FA deve conter exatamente 6 dígitos";
        }
        return null;
    }
} 