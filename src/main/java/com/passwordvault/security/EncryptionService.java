package com.passwordvault.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Serviço responsável por toda a criptografia e segurança do sistema.
 * Implementa criptografia AES-GCM para máxima segurança, usando uma chave derivada da senha mestra.
 */
public class EncryptionService {
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 65536; // Recomendado pela OWASP
    private static final int KEY_LENGTH = 256; // AES-256
    private final SecretKey secretKey;
    private final SecureRandom secureRandom;

    // O sal para PBKDF2 deve ser armazenado junto com os dados criptografados
    // ou derivado de uma forma consistente (por exemplo, do ID do usuário mestre).
    // Para simplificar AGORA, vamos usar um sal fixo, mas ISSO NÃO É SEGURO para produção.
    // TODO: Gerar e armazenar um sal único por usuário mestre.
    private static final byte[] SALT = "thisisafixedsaltfornow".getBytes(StandardCharsets.UTF_8);

    public EncryptionService(SecretKey secretKey) throws Exception {
        this.secureRandom = new SecureRandom();
        this.secretKey = secretKey;
    }

    // Método para derivar a chave a partir da senha mestra
    public static SecretKey deriveKey(String masterPassword) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), SALT, ITERATIONS, KEY_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    /**
     * Criptografa uma string usando AES-GCM
     * @param plaintext texto a ser criptografado
     * @return string criptografada em Base64 (IV + Ciphertext)
     */
    public String encrypt(String plaintext) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv); // Gerar um IV único para cada criptografia

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, parameterSpec);

        byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        
        // Concatenar IV e Ciphertext para armazenar
        byte[] encrypted = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(cipherText, 0, encrypted, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Descriptografa uma string criptografada com AES-GCM
     * @param encryptedText texto criptografado em Base64 (IV + Ciphertext)
     * @return texto original
     */
    public String decrypt(String encryptedText) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encryptedText);
        
        // Extrair IV e Ciphertext
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(decoded, 0, iv, 0, iv.length);

        byte[] cipherText = new byte[decoded.length - GCM_IV_LENGTH];
        System.arraycopy(decoded, GCM_IV_LENGTH, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, this.secretKey, parameterSpec);

        byte[] plaintext = cipher.doFinal(cipherText);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

     /**
     * Gera uma senha forte e aleatória
     * @param length tamanho da senha
     * @return senha gerada
     */
    public String generateStrongPassword(int length) {
        String upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowerChars = "abcdefghijklmnopqrstuvwxyz";
        String numbers = "0123456789";
        String specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        String allChars = upperChars + lowerChars + numbers + specialChars;

        StringBuilder password = new StringBuilder();

        // Garante pelo menos um caractere de cada tipo
        password.append(upperChars.charAt(secureRandom.nextInt(upperChars.length())));
        password.append(lowerChars.charAt(secureRandom.nextInt(lowerChars.length())));
        password.append(numbers.charAt(secureRandom.nextInt(numbers.length())));
        password.append(specialChars.charAt(secureRandom.nextInt(specialChars.length())));

        // Completa o resto da senha
        for (int i = 4; i < length; i++) {
            password.append(allChars.charAt(secureRandom.nextInt(allChars.length())));
        }

        // Embaralha a senha
        char[] passwordArray = password.toString().toCharArray();
        for (int i = passwordArray.length - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            char temp = passwordArray[i];
            passwordArray[i] = passwordArray[j];
            passwordArray[j] = temp;
        }

        return new String(passwordArray);
    }
} 