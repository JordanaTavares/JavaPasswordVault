package com.passwordvault.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionServiceTest {
    private EncryptionService encryptionService;
    private SecretKey testKey; // Adicionado para a chave de teste

    @BeforeEach
    void setUp() throws Exception {
        // Gerar uma chave de teste para usar no EncryptionService
        this.testKey = generateTestKey();
        encryptionService = new EncryptionService(this.testKey); // Passar a chave para o construtor
    }

    // Método auxiliar para gerar uma chave AES para os testes
    private SecretKey generateTestKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    @Test
    void testEncryptionAndDecryption() throws Exception {
        String originalText = "Senha123!@#";
        String encrypted = encryptionService.encrypt(originalText);
        String decrypted = encryptionService.decrypt(encrypted);

        assertNotEquals(originalText, encrypted, "O texto criptografado deve ser diferente do original");
        assertEquals(originalText, decrypted, "O texto descriptografado deve ser igual ao original");
    }

    @Test
    void testGenerateStrongPassword() {
        int length = 12;
        String password = encryptionService.generateStrongPassword(length);

        assertEquals(length, password.length(), "A senha deve ter o tamanho especificado");
        assertTrue(password.matches(".*[A-Z].*"), "A senha deve conter pelo menos uma letra maiúscula");
        assertTrue(password.matches(".*[a-z].*"), "A senha deve conter pelo menos uma letra minúscula");
        assertTrue(password.matches(".*[0-9].*"), "A senha deve conter pelo menos um número");
        assertTrue(password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?].*"), "A senha deve conter pelo menos um caractere especial");
    }

    @Test
    void testDifferentEncryptions() throws Exception {
        String text = "Senha123!@#";
        String encrypted1 = encryptionService.encrypt(text);
        String encrypted2 = encryptionService.encrypt(text);

        assertNotEquals(encrypted1, encrypted2, "Cada criptografia deve gerar um resultado diferente");
    }
} 