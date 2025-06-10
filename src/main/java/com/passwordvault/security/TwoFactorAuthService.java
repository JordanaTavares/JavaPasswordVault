package com.passwordvault.security;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import java.util.concurrent.TimeUnit;

/**
 * Serviço responsável pela autenticação de dois fatores usando Google Authenticator.
 */
public class TwoFactorAuthService {
    private final GoogleAuthenticator gAuth;
    private String secretKey;
    private String username;

    public TwoFactorAuthService() {
        // Configurar o GoogleAuthenticator com uma janela de tempo maior
        GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
            .setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(30)) // Período padrão de 30 segundos
            .setWindowSize(2) // Aceita 1 intervalo antes e depois
            .setCodeDigits(6) // Código de 6 dígitos
            .build();
        this.gAuth = new GoogleAuthenticator(config);
    }

    /**
     * Define o nome do usuário para o QR code
     * @param username nome do usuário
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Gera uma nova chave secreta para autenticação de dois fatores
     * @return URL para QR Code do Google Authenticator
     */
    public String generateNewSecretKey() {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        this.secretKey = key.getKey();
        String issuer = "PasswordVault";
        String account = username != null ? username : "user@example.com";
        
        // Log para debug
        System.out.println("\nDebug 2FA - Nova chave gerada:");
        System.out.println("Username: " + account);
        System.out.println("Secret Key: " + this.secretKey);
        
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL(issuer, account, key);
    }

    /**
     * Verifica se o código TOTP fornecido é válido
     * @param code código TOTP fornecido pelo usuário
     * @return true se o código for válido
     */
    public boolean verifyCode(int code) {
        if (secretKey == null || secretKey.isEmpty()) {
            System.err.println("Erro: Chave secreta não definida");
            return false;
        }

        // Log detalhado para debug
        System.out.println("\nDebug 2FA - Verificação de código:");
        System.out.println("Código fornecido: " + code);
        System.out.println("Chave secreta: " + secretKey);
        
        // Obter o código esperado atual
        long currentTime = System.currentTimeMillis() / 1000L;
        int expectedCode = gAuth.getTotpPassword(secretKey);
        
        System.out.println("Timestamp atual: " + currentTime);
        System.out.println("Código esperado atual: " + expectedCode);
        
        // Verificar o código
        boolean isValid = gAuth.authorize(secretKey, code);
        System.out.println("Resultado da verificação: " + (isValid ? "VÁLIDO" : "INVÁLIDO"));
        
        if (!isValid) {
            // Se inválido, mostrar códigos válidos na janela de tempo
            System.out.println("\nCódigos válidos na janela de tempo:");
            long timeWindow = currentTime - 30; // 30 segundos antes
            for (int i = 0; i < 3; i++) { // Mostrar 3 intervalos
                int windowCode = gAuth.getTotpPassword(secretKey, timeWindow + (i * 30));
                System.out.println("Código para T" + (i-1) + ": " + windowCode);
            }
        }
        
        return isValid;
    }

    /**
     * Retorna a chave secreta atual
     * @return chave secreta em formato string
     */
    public String getSecretKey() {
        return this.secretKey;
    }

    /**
     * Define uma chave secreta existente
     * @param secretKey chave secreta em formato string
     */
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
        
        // Log para debug
        System.out.println("\nDebug 2FA - Chave definida:");
        System.out.println("Nova chave secreta: " + this.secretKey);
    }
} 