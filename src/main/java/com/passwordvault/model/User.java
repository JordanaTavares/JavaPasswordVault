package com.passwordvault.model;

/**
 * Representa um usuário do sistema.
 */
public class User {
    private int userId;
    private String username;
    private String hashedPassword;
    private String twoFactorSecret;
    private String encryptionSalt;

    // Construtor para carregar do BD
    public User(int userId, String username, String hashedPassword, String twoFactorSecret, String encryptionSalt) {
        this.userId = userId;
        this.username = username;
        this.hashedPassword = hashedPassword;
        this.twoFactorSecret = twoFactorSecret;
        this.encryptionSalt = encryptionSalt;
    }

    // Construtor para criar novo usuário (o ID será gerado pelo BD)
    public User(String username, String hashedPassword, String twoFactorSecret, String encryptionSalt) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        this.twoFactorSecret = twoFactorSecret;
        this.encryptionSalt = encryptionSalt;
    }

    // Getters
    public int getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public String getHashedPassword() {
        return hashedPassword;
    }

    public String getTwoFactorSecret() {
        return twoFactorSecret;
    }

    public String getEncryptionSalt() {
        return encryptionSalt;
    }

    // Setter para o ID (usado após salvar no BD)
    public void setUserId(int userId) {
        this.userId = userId;
    }

    // TODO: Adicionar setters se necessário, mas manter a imutabilidade onde possível

    @Override
    public String toString() {
        return "User{" +
               "userId=" + userId +
               ", username='" + username + '\'' +
               // Não incluir hashed_password, twoFactorSecret ou encryptionSalt no toString por segurança
               '}';
    }
} 