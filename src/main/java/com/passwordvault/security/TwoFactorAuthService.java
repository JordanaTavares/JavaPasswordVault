package com.passwordvault.security;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;

/**
 * Serviço responsável pela autenticação de dois fatores usando Google Authenticator.
 */
public class TwoFactorAuthService {
    private final GoogleAuthenticator gAuth;
    private String secretKey;

    public TwoFactorAuthService() {
        this.gAuth = new GoogleAuthenticator();
    }

    /**
     * Gera uma nova chave secreta para autenticação de dois fatores
     * @return URL para QR Code do Google Authenticator
     */
    public String generateNewSecretKey() {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        this.secretKey = key.getKey();
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL("PasswordVault", "user@example.com", key);
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

        // Adicionar margem de tempo para compensar pequenas diferenças de relógio
        boolean isValid = gAuth.authorize(secretKey, code);
        
        // Log para debug
        System.out.println("Verificando código 2FA:");
        System.out.println("Código recebido: " + code);
        System.out.println("Chave secreta: " + secretKey);
        System.out.println("Resultado da verificação: " + isValid);
        
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
    }
} 