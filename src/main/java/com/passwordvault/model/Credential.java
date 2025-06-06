package com.passwordvault.model;

import com.passwordvault.utils.ConsoleUtils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Classe que representa uma credencial armazenada no gerenciador de senhas.
 * Contém informações sobre o serviço, email e senha associados.
 */
public class Credential {
    private String id;
    private String service;
    private String email;
    private String encryptedPassword;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private boolean isCompromised;
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");

    public Credential(String service, String email, String encryptedPassword) {
        this.id = java.util.UUID.randomUUID().toString();
        this.service = service;
        this.email = email;
        this.encryptedPassword = encryptedPassword;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
        this.isCompromised = false;
    }

    // Getters e Setters
    public String getId() {
        return id;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
        this.updatedAt = LocalDateTime.now();
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
        this.updatedAt = LocalDateTime.now();
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
        this.updatedAt = LocalDateTime.now();
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

    public void setCompromised(boolean compromised) {
        isCompromised = compromised;
        this.updatedAt = LocalDateTime.now();
    }

    @Override
    public String toString() {
        return String.format("%sServiço: %s%s\n%sEmail: %s%s\n%sÚltima atualização: %s%s\n%sStatus: %s%s",
                ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                ConsoleUtils.WHITE,
                ConsoleUtils.RESET,
                ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                ConsoleUtils.WHITE,
                ConsoleUtils.RESET,
                ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                ConsoleUtils.WHITE,
                ConsoleUtils.RESET,
                ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                isCompromised ? ConsoleUtils.RED + "COMPROMETIDO" : ConsoleUtils.GREEN + "Seguro",
                ConsoleUtils.RESET);
    }
} 