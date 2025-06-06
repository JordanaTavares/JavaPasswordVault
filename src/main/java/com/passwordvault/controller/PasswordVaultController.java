package com.passwordvault.controller;

import com.passwordvault.model.Credential;
import com.passwordvault.model.MasterUser;
import com.passwordvault.repository.CredentialRepository;
import com.passwordvault.repository.MasterUserRepository;
import com.passwordvault.security.EncryptionService;
import com.passwordvault.security.PasswordBreachChecker;
import com.passwordvault.security.TwoFactorAuthService;
import com.passwordvault.utils.ConsoleUtils;
import com.passwordvault.utils.ValidationUtils;
import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.SecretKey;
import java.util.List;
import java.util.Scanner;

/**
 * Controlador principal que gerencia todas as operações do sistema.
 */
public class PasswordVaultController {
    private CredentialRepository repository; // Não final, será inicializado após autenticação
    private final MasterUserRepository masterUserRepository;
    private EncryptionService encryptionService; // Não final, será inicializado após autenticação
    private final PasswordBreachChecker breachChecker;
    private final TwoFactorAuthService twoFactorAuth;
    private final Scanner scanner;
    private boolean isAuthenticated;
    private MasterUser masterUser; // Adicionado para guardar o usuário mestre logado
    private String temporaryMasterPassword; // Para guardar a senha mestra digitada durante a autenticação

    public PasswordVaultController() throws Exception {
        this.masterUserRepository = new MasterUserRepository();
        // encryptionService e repository serão inicializados após autenticação
        this.breachChecker = new PasswordBreachChecker();
        this.twoFactorAuth = new TwoFactorAuthService();
        this.scanner = new Scanner(System.in);
        this.isAuthenticated = false;
    }

    /**
     * Inicia o sistema e gerencia o fluxo principal
     */
    public void start() {
        ConsoleUtils.clearScreen();
        ConsoleUtils.printHeader("Gerenciador de Senhas Seguro");

        if (!masterUserRepository.exists()) {
            ConsoleUtils.printInfo("\nPrimeira execução! Vamos configurar seu usuário mestre.");
            setupMasterUser();
        } else {
            authenticateMasterUser();
        }

        if (isAuthenticated) {
             try {
                // Derivar a chave a partir da senha mestra digitada
                SecretKey derivedKey = EncryptionService.deriveKey(temporaryMasterPassword);

                // Inicializar serviços e repositórios com a chave derivada
                this.encryptionService = new EncryptionService(derivedKey);
                this.repository = new CredentialRepository(this.encryptionService);

                ConsoleUtils.printSuccess("Configuração inicial concluída. Entrando no menu principal...");

             } catch (Exception e) {
                 ConsoleUtils.printError("Erro durante a inicialização pós-autenticação: " + e.getMessage());
                 e.printStackTrace();
                 System.exit(1);
             }

            while (isAuthenticated) {
                showMenu();
                int choice = getIntInput("Escolha uma opção: ");
                processChoice(choice);
            }
        } else {
            ConsoleUtils.printInfo("\nAutenticação falhou ou foi cancelada. Saindo...");
        }
    }

    private void setupMasterUser() {
        ConsoleUtils.printHeader("Configuração do Usuário Mestre");

        String masterPassword = getValidatedInput("Crie sua senha mestra: ", ValidationUtils::validatePassword);
        String confirmPassword = getStringInput("Confirme sua senha mestra: ");

        if (!masterPassword.equals(confirmPassword)) {
            ConsoleUtils.printError("As senhas não coincidem. Tente novamente.");
            setupMasterUser(); // Tentar novamente
            return;
        }

        // Criptografar a senha mestra para armazenamento (NÃO é a chave de criptografia de dados)
        String hashedPassword = BCrypt.hashpw(masterPassword, BCrypt.gensalt());

        // Configurar 2FA
        ConsoleUtils.printInfo("\nVamos configurar a autenticação de dois fatores.");
        String qrCodeUrl = twoFactorAuth.generateNewSecretKey();
        ConsoleUtils.printInfo("Escaneie o QR Code com o Google Authenticator:");
        System.out.println(qrCodeUrl);
        ConsoleUtils.printWarning("Guarde esta chave secreta em um lugar seguro: " + twoFactorAuth.getSecretKey());

        String code = getValidatedInput("Digite o código do Google Authenticator para verificar: ", ValidationUtils::validate2FACode);

        if (twoFactorAuth.verifyCode(Integer.parseInt(code))) {
            this.masterUser = new MasterUser(hashedPassword, twoFactorAuth.getSecretKey());
            masterUserRepository.saveMasterUser(this.masterUser);
            ConsoleUtils.printSuccess("\nUsuário mestre configurado com sucesso!");
            ConsoleUtils.printInfo("Por favor, execute o programa novamente para fazer login.");
            isAuthenticated = false; // Não autentica automaticamente após a configuração
        } else {
            ConsoleUtils.printError("Código 2FA inválido. Configuração falhou. Tente novamente.");
            setupMasterUser(); // Tentar novamente a configuração
        }
    }

    private void authenticateMasterUser() {
        ConsoleUtils.printHeader("Autenticação do Usuário Mestre");
        this.masterUser = masterUserRepository.loadMasterUser(); // Carregar o usuário mestre

        if (this.masterUser == null) {
             ConsoleUtils.printError("Erro fatal: Usuário mestre não encontrado no arquivo.");
             System.exit(1);
        }

        String enteredPassword = getStringInput("Digite sua senha mestra: ");

        if (BCrypt.checkpw(enteredPassword, this.masterUser.getHashedPassword())) {
            ConsoleUtils.printSuccess("Senha mestra correta.");
            this.temporaryMasterPassword = enteredPassword; // Armazenar temporariamente
            // Configurar 2FA com a chave secreta salva
            twoFactorAuth.setSecretKey(this.masterUser.getTwoFactorSecret());
            authenticate2FA(); // Prosseguir para autenticação 2FA
        } else {
            ConsoleUtils.printError("Senha mestra incorreta.");
            authenticateMasterUser(); // Tentar novamente
        }
    }

    private void authenticate2FA() {
        ConsoleUtils.printHeader("Autenticação 2FA");
        String code = getValidatedInput("Digite o código do Google Authenticator: ", ValidationUtils::validate2FACode);

        if (twoFactorAuth.verifyCode(Integer.parseInt(code))) {
            isAuthenticated = true;
            ConsoleUtils.printSuccess("Autenticação 2FA bem-sucedida!");
        } else {
            ConsoleUtils.printError("Código 2FA inválido.");
            authenticate2FA(); // Tentar novamente
        }
    }

    private void showMenu() {
        ConsoleUtils.clearScreen();
        ConsoleUtils.printHeader(" MENU PRINCIPAL ");
        System.out.println(); // Adiciona uma linha em branco para espaçamento
        ConsoleUtils.printMenuOption(1, "Adicionar nova credencial");
        ConsoleUtils.printMenuOption(2, "Listar todas as credenciais");
        ConsoleUtils.printMenuOption(3, "Buscar credencial por serviço");
        ConsoleUtils.printMenuOption(4, "Gerar senha forte");
        ConsoleUtils.printMenuOption(5, "Verificar senha");
        ConsoleUtils.printMenuOption(6, "Sair");
        System.out.println(); // Adiciona uma linha em branco para espaçamento
        ConsoleUtils.printInfo("Use os números para selecionar uma opção.");
        ConsoleUtils.printDivider();
    }

    private void processChoice(int choice) {
        try {
            switch (choice) {
                case 1 -> addCredential();
                case 2 -> listCredentials();
                case 3 -> searchByService();
                case 4 -> generatePassword();
                case 5 -> checkPassword();
                case 6 -> {
                    isAuthenticated = false;
                    ConsoleUtils.printInfo("Saindo...");
                }
                default -> ConsoleUtils.printError("Opção inválida!");
            }
        } catch (Exception e) {
            ConsoleUtils.printError("Erro: " + e.getMessage());
            e.printStackTrace(); // Imprimir stack trace para depuração
        }
    }

    private void addCredential() throws Exception {
        ConsoleUtils.printHeader("Adicionar Nova Credencial");

        String service = getValidatedInput("Serviço: ", ValidationUtils::validateService);
        String email = getValidatedInput("Email: ", ValidationUtils::validateEmail);
        String password = getValidatedInput("Senha: ", ValidationUtils::validatePassword);

        // Criptografar a senha da credencial antes de salvar
        String encryptedPassword = encryptionService.encrypt(password);
        Credential credential = new Credential(service, email, encryptedPassword);
        repository.addCredential(credential);
        ConsoleUtils.printSuccess("Credencial adicionada com sucesso!");
    }

    private void listCredentials() {
        ConsoleUtils.printHeader("Credenciais");
        List<Credential> credentials = repository.findAll();
        if (credentials.isEmpty()) {
            ConsoleUtils.printInfo("Nenhuma credencial cadastrada.");
            return;
        }

        for (Credential credential : credentials) {
            ConsoleUtils.printDivider();
            // Descriptografar a senha antes de exibir
            try {
                 String decryptedPassword = encryptionService.decrypt(credential.getEncryptedPassword());
                 // Exibir as informações da credencial, incluindo a senha descriptografada
                 ConsoleUtils.printInfo(String.format("Serviço: %s\nEmail: %s\nSenha: %s\nÚltima atualização: %s\nStatus: %s",
                         credential.getService(),
                         credential.getEmail(),
                         decryptedPassword, // Exibir senha descriptografada
                         credential.getUpdatedAt(),
                         credential.isCompromised() ? "COMPROMETIDO" : "Seguro"));
            } catch (Exception e) {
                 ConsoleUtils.printError("Erro ao descriptografar credencial: " + e.getMessage());
                 // Decide how to handle this - maybe skip this credential or show an error indicator
                 ConsoleUtils.printWarning("Não foi possível exibir esta credencial devido a um erro de descriptografia.");
            }
        }
    }

    private void searchByService() {
        ConsoleUtils.printHeader("Buscar por Serviço");
        String service = getValidatedInput("Nome do serviço: ", ValidationUtils::validateService);
        List<Credential> credentials = repository.findByService(service);

        if (credentials.isEmpty()) {
            ConsoleUtils.printInfo("Nenhuma credencial encontrada para este serviço.");
            return;
        }

        for (Credential credential : credentials) {
            ConsoleUtils.printDivider();
            // Descriptografar a senha antes de exibir
             try {
                 String decryptedPassword = encryptionService.decrypt(credential.getEncryptedPassword());
                  // Exibir as informações da credencial, incluindo a senha descriptografada
                 ConsoleUtils.printInfo(String.format("Serviço: %s\nEmail: %s\nSenha: %s\nÚltima atualização: %s\nStatus: %s",
                         credential.getService(),
                         credential.getEmail(),
                         decryptedPassword, // Exibir senha descriptografada
                         credential.getUpdatedAt(),
                         credential.isCompromised() ? "COMPROMETIDO" : "Seguro"));
            } catch (Exception e) {
                 ConsoleUtils.printError("Erro ao descriptografar credencial: " + e.getMessage());
                 // Decide how to handle this - maybe skip this credential or show an error indicator
                 ConsoleUtils.printWarning("Não foi possível exibir esta credencial devido a um erro de descriptografia.");
            }
        }
    }

    private void generatePassword() {
        ConsoleUtils.printHeader("Gerar Senha Forte");
        int length = getIntInput("Tamanho da senha (mínimo 8): ");
        if (length < 8) {
            ConsoleUtils.printError("Tamanho mínimo é 8 caracteres!");
            return;
        }

        String password = encryptionService.generateStrongPassword(length);
        ConsoleUtils.printSuccess("\nSenha gerada: " + password);
    }

    private void checkPassword() {
        ConsoleUtils.printHeader("Verificar Senha");
        String password = getValidatedInput("Digite a senha para verificar: ", ValidationUtils::validatePassword);
        int breaches = breachChecker.checkPassword(password);

        if (breaches > 0) {
            ConsoleUtils.printWarning("⚠️ ATENÇÃO: Esta senha foi vazada " + breaches + " vezes!");
        } else {
            ConsoleUtils.printSuccess("✅ Esta senha não foi encontrada em vazamentos conhecidos.");
        }
    }

    private String getStringInput(String prompt) {
        System.out.print(prompt);
        return scanner.nextLine();
    }

    private int getIntInput(String prompt) {
        while (true) {
            try {
                System.out.print(prompt);
                return Integer.parseInt(scanner.nextLine());
            } catch (NumberFormatException e) {
                ConsoleUtils.printError("Por favor, digite um número válido.");
            }
        }
    }

    private String getValidatedInput(String prompt, java.util.function.Function<String, String> validator) {
        while (true) {
            String input = getStringInput(prompt);
            String error = validator.apply(input);
            if (error == null) {
                return input;
            }
            ConsoleUtils.printError(error);
        }
    }
} 