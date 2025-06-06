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
        this.secretKey = null;
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
        if (secretKey == null) {
            throw new IllegalStateException("Chave secreta não foi gerada");
        }
        return gAuth.authorize(secretKey, code);
    }

    /**
     * Retorna a chave secreta atual
     * @return chave secreta em formato string
     */
    public String getSecretKey() {
        return secretKey;
    }

    /**
     * Define uma chave secreta existente
     * @param secretKey chave secreta em formato string
     */
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }
} 