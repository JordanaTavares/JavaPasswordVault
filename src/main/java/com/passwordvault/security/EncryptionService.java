package com.passwordvault.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Serviço responsável por operações de criptografia e descriptografia usando AES/GCM/NoPadding.
 * Utiliza PBKDF2 para derivação segura da chave a partir da senha mestra.
 */
public class EncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    private final SecretKey secretKey;

    public EncryptionService(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * Deriva uma chave secreta a partir de uma senha e um sal usando PBKDF2WithHmacSHA256.
     * Esta chave é usada para criptografar e descriptografar as credenciais.
     * @param password A senha mestra do usuário.
     * @param salt O sal único do usuário.
     * @return A chave secreta derivada.
     * @throws NoSuchAlgorithmException se o algoritmo não estiver disponível.
     * @throws InvalidKeySpecException se a especificação da chave for inválida.
     */
    public static SecretKey deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKey pbeKey = factory.generateSecret(spec);
        return new SecretKeySpec(pbeKey.getEncoded(), "AES");
    }

    /**
     * Criptografa um texto simples usando AES/GCM/NoPadding.
     * O IV é gerado randomicamente e prependado ao texto cifrado.
     * @param plaintext O texto a ser criptografado.
     * @return O texto cifrado codificado em Base64, incluindo o IV.
     * @throws Exception se ocorrer um erro durante a criptografia.
     */
    public String encrypt(String plaintext) throws Exception {
        byte[] iv = new byte[IV_LENGTH_BYTE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, parameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] encryptedData = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(ciphertext, 0, encryptedData, iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(encryptedData);
    }

    /**
     * Descriptografa um texto cifrado usando AES/GCM/NoPadding.
     * Espera que o texto cifrado esteja codificado em Base64 e contenha o IV prependado.
     * @param ciphertextBase64 O texto cifrado codificado em Base64.
     * @return O texto simples original.
     * @throws Exception se ocorrer um erro durante a descriptografia (incluindo autenticação falha do GCM).
     */
    public String decrypt(String ciphertextBase64) throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(ciphertextBase64);

        if (encryptedData.length < IV_LENGTH_BYTE + (TAG_LENGTH_BIT / 8)) {
             throw new IllegalArgumentException("Dados cifrados inválidos ou truncados.");
        }

        byte[] iv = new byte[IV_LENGTH_BYTE];
        System.arraycopy(encryptedData, 0, iv, 0, IV_LENGTH_BYTE);

        int ciphertextLength = encryptedData.length - IV_LENGTH_BYTE;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(encryptedData, IV_LENGTH_BYTE, ciphertext, 0, ciphertextLength);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, this.secretKey, parameterSpec);

        // A autenticação GCM ocorre durante o doFinal. Se falhar, uma AEADBadTagException é lançada.
        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * Gera uma senha forte e aleatória.
     * @param length O comprimento desejado da senha.
     * @return Uma senha forte.
     */
    public String generateStrongPassword(int length) {
        String upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowerCase = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String specialChars = "!@#$%^&*()-_=+";

        String allChars = upperCase + lowerCase + digits + specialChars;
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);
        
        // Garantir que a senha contenha pelo menos um caractere de cada tipo
        password.append(upperCase.charAt(random.nextInt(upperCase.length())));
        password.append(lowerCase.charAt(random.nextInt(lowerCase.length())));
        password.append(digits.charAt(random.nextInt(digits.length())));
        password.append(specialChars.charAt(random.nextInt(specialChars.length())));

        // Preencher o restante do comprimento com caracteres aleatórios de todos os tipos
        for (int i = 4; i < length; i++) {
            password.append(allChars.charAt(random.nextInt(allChars.length())));
        }

        // Embaralhar a senha para garantir aleatoriedade (os primeiros 4 caracteres não ficarem sempre no início)
        char[] passwordChars = password.toString().toCharArray();
        for (int i = 0; i < passwordChars.length; i++) {
            int randomIndex = random.nextInt(passwordChars.length);
            char temp = passwordChars[i];
            passwordChars[i] = passwordChars[randomIndex];
            passwordChars[randomIndex] = temp;
        }

        return new String(passwordChars);
    }
} 