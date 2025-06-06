package com.passwordvault;

import com.passwordvault.controller.PasswordVaultController;

/**
 * Classe principal que inicia a aplicação.
 */
public class Main {
    public static void main(String[] args) {
        try {
            PasswordVaultController controller = new PasswordVaultController();
            controller.start();
        } catch (Exception e) {
            System.err.println("Erro fatal: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
} 