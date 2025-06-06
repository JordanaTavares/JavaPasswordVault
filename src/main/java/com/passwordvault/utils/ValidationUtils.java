package com.passwordvault.utils;

import java.util.regex.Pattern;

/**
 * Classe utilitária para validação de dados de entrada.
 */
public class ValidationUtils {

    // Regex para validar senha: mínimo 8 caracteres, pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial.
    // Inclui caracteres especiais gerados: !@#$%^&*()-_=+
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()\\-_=+]?)[A-Za-z\\d!@#$%^&*()\\-_=+]{8,}$");

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

    /**
     * Valida se uma senha atende aos critérios de segurança.
     * @param password A senha a ser validada.
     * @return null se a senha for válida, ou uma mensagem de erro caso contrário.
     */
    public static String validatePassword(String password) {
        if (password == null || password.isEmpty()) {
            return "A senha não pode estar vazia.";
        }
        if (password.length() < 8) {
            return "A senha deve ter pelo menos 8 caracteres.";
        }
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            return "A senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial (@$!%*?&).";
        }
        return null;
    }

    /**
     * Valida se um email tem um formato válido.
     * @param email O email a ser validado.
     * @return null se o email for válido, ou uma mensagem de erro caso contrário.
     */
    public static String validateEmail(String email) {
         if (email == null || email.trim().isEmpty()) {
             // Email é opcional em Credential, mas se fornecido, deve ser válido.
             // Permitimos vazio aqui se o campo for opcional na UI/entrada.
             return null;
         }
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return "Formato de email inválido.";
        }
        return null;
    }

    /**
     * Valida se um nome de serviço não está vazio.
     * @param service O nome do serviço a ser validado.
     * @return null se o serviço for válido, ou uma mensagem de erro caso contrário.
     */
    public static String validateService(String service) {
        if (service == null || service.trim().isEmpty()) {
            return "O nome do serviço não pode estar vazio.";
        }
        return null;
    }

    /**
     * Valida se um código 2FA é um número de 6 dígitos.
     * @param code O código 2FA a ser validado (como String).
     * @return null se o código for válido, ou uma mensagem de erro caso contrário.
     */
    public static String validate2FACode(String code) {
        if (code == null || code.length() != 6) {
            return "O código 2FA deve ter 6 dígitos.";
        }
        try {
            Integer.parseInt(code);
            return null;
        } catch (NumberFormatException e) {
            return "O código 2FA deve conter apenas números.";
        }
    }
} 