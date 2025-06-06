package com.passwordvault.model;

public class MasterUser {
    private String hashedPassword;
    private String twoFactorSecret;

    // Construtor
    public MasterUser(String hashedPassword, String twoFactorSecret) {
        this.hashedPassword = hashedPassword;
        this.twoFactorSecret = twoFactorSecret;
    }

    // Getters
    public String getHashedPassword() {
        return hashedPassword;
    }

    public String getTwoFactorSecret() {
        return twoFactorSecret;
    }

    // Setters
    public void setHashedPassword(String hashedPassword) {
        this.hashedPassword = hashedPassword;
    }

    public void setTwoFactorSecret(String twoFactorSecret) {
        this.twoFactorSecret = twoFactorSecret;
    }
} 