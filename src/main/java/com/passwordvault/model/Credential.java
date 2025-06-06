package com.passwordvault.model;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Representa uma credencial armazenada no sistema.
 */
public class Credential {
    private int credentialId; // ID local do banco de dados (AUTO_INCREMENT)
    private UUID id; // ID universal (UUID) para sincronização
    private String service;
    private String email;
    private String password; // Senha (pode ser pura ou descriptografada dependendo do uso)
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private boolean isCompromised;
    private int userId; // Novo campo para armazenar o ID do usuário

    // Construtor para carregar do BD
    public Credential(int credentialId, UUID id, String service, String email, String password, LocalDateTime createdAt, LocalDateTime updatedAt, boolean isCompromised, int userId) {
        this.credentialId = credentialId;
        this.id = id;
        this.service = service;
        this.email = email;
        this.password = password; // Ao carregar, esta é a senha descriptografada
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.isCompromised = isCompromised;
        this.userId = userId;
    }

    // Construtor para criar nova credencial
    public Credential(String service, String email, String password) {
        this.id = UUID.randomUUID(); // Gerar um novo UUID
        this.service = service;
        this.email = email;
        this.password = password; // Ao criar, esta é a senha pura digitada
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
        this.isCompromised = false;
    }

    // Getters

    public int getCredentialId() {
        return credentialId;
    }

    public UUID getId() {
        return id;
    }

    public String getService() {
        return service;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public boolean isCompromised() {
        return isCompromised;
    }

    public int getUserId() {
        return userId;
    }

    // Setters (apenas para campos que podem mudar ou ser definidos após a criação)

    public void setCredentialId(int credentialId) {
        this.credentialId = credentialId;
    }

    // setPassword pode ser útil se houver lógica para atualizar a senha em memória,
    // mas a atualização no BD deve passar pela criptografia no repositório.
    public void setPassword(String password) {
        this.password = password;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public void setCompromised(boolean compromised) {
        isCompromised = compromised;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    // Omitindo setters para campos que não devem mudar após a criação (id, service, email, createdAt)

    @Override
    public String toString() {
        return "Credential{" +
               "credentialId=" + credentialId +
               ", id=" + id +
               ", service='" + service + '\'' +
               ", email='" + email + '\'' +
               // Não incluir senha no toString por segurança
               ", createdAt=" + createdAt +
               ", updatedAt=" + updatedAt +
               ", isCompromised=" + isCompromised +
               ", userId=" + userId +
               '}';
    }
} 