package com.passwordvault.controller;

import com.passwordvault.model.Credential;
import com.passwordvault.model.User;
import com.passwordvault.repository.DatabaseCredentialRepository;
import com.passwordvault.repository.DatabaseUserRepository;
import com.passwordvault.security.EncryptionService;
import com.passwordvault.security.PasswordBreachChecker;
import com.passwordvault.security.TwoFactorAuthService;
import com.passwordvault.utils.ConsoleUtils;
import com.passwordvault.utils.ValidationUtils;
import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.List;
import java.util.Scanner;
import java.util.Base64;
import java.util.ArrayList;

/**
 * Controlador principal que gerencia todas as operações do sistema.
 */
public class PasswordVaultController {
    private DatabaseCredentialRepository credentialRepository; // Repositório de credenciais baseado em BD
    private final DatabaseUserRepository userRepository; // Repositório de usuários baseado em BD
    private EncryptionService encryptionService; // Inicializado após autenticação com a chave derivada
    private final PasswordBreachChecker breachChecker;
    private final TwoFactorAuthService twoFactorAuth;
    private final Scanner scanner;
    private boolean isAuthenticated;
    private User loggedInUser; // Para guardar o usuário logado
    private String tempMasterPassword; // Campo temporário para armazenar a senha mestra digitada

    private static final int SALT_LENGTH = 16;
    private final SecureRandom secureRandom;

    public PasswordVaultController() throws Exception {
        this.userRepository = new DatabaseUserRepository();
        this.breachChecker = new PasswordBreachChecker();
        this.twoFactorAuth = new TwoFactorAuthService();
        this.scanner = new Scanner(System.in);
        this.isAuthenticated = false;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Inicia o sistema e gerencia o fluxo principal.
     * Trata a configuração inicial do usuário e a autenticação.
     */
    public void start() {
        ConsoleUtils.clearScreen();
        ConsoleUtils.printHeader("Gerenciador de Senhas Seguro");

        try {
            if (!userRepository.userExists("admin")) {
                ConsoleUtils.printInfo("\nPrimeira execução! Vamos configurar o primeiro usuário (admin).");
                setupFirstUser();
            } else {
                authenticateUser();
            }

            if (isAuthenticated && loggedInUser != null) {
                this.tempMasterPassword = null; // Limpar a senha mestra temporária da memória

                ConsoleUtils.printSuccess("Autenticação bem-sucedida! Entrando no menu principal...");

                while (isAuthenticated) {
                    showMenu();
                    int choice = getIntInput("Escolha uma opção: ");
                    processChoice(choice);
                }
            } else {
                 if (!isAuthenticated) {
                     ConsoleUtils.printInfo("\nAutenticação falhou ou foi cancelada. Saindo...");
                 }
            }
        } catch (SQLException e) {
             ConsoleUtils.printError("Erro de banco de dados durante a inicialização: " + e.getMessage());
             System.exit(1);
        } catch (Exception e) {
             ConsoleUtils.printError("Ocorreu um erro inesperado durante a inicialização: " + e.getMessage());
             System.exit(1);
        }
    }

    /**
     * Configura o primeiro usuário (usuário admin) se nenhum existir.
     */
    private void setupFirstUser() {
        ConsoleUtils.printHeader("Configuração do Primeiro Usuário");

        String username = getValidatedInput("Escolha um nome de usuário (ex: admin): ", this::validateUsername);
        String masterPassword = getValidatedInput("Crie sua senha mestra: ", ValidationUtils::validatePassword);
        String confirmPassword = getStringInput("Confirme sua senha mestra: ");

        if (!masterPassword.equals(confirmPassword)) {
            ConsoleUtils.printError("As senhas não coincidem. Tente novamente.");
            setupFirstUser();
            return;
        }

        byte[] saltBytes = new byte[SALT_LENGTH];
        secureRandom.nextBytes(saltBytes);
        String encryptionSalt = Base64.getEncoder().encodeToString(saltBytes);

        ConsoleUtils.printInfo("\nVamos configurar a autenticação de dois fatores.");
        String qrCodeUrl = twoFactorAuth.generateNewSecretKey();
        ConsoleUtils.printInfo("Escaneie o QR Code com o Google Authenticator:");
        System.out.println(qrCodeUrl);
        ConsoleUtils.printWarning("Guarde esta chave secreta em um lugar seguro: " + twoFactorAuth.getSecretKey());

        String code = getValidatedInput("Digite o código do Google Authenticator para verificar: ", ValidationUtils::validate2FACode);

        if (twoFactorAuth.verifyCode(Integer.parseInt(code))) {
            try {
                 User newUser = new User(username, BCrypt.hashpw(masterPassword, BCrypt.gensalt()), twoFactorAuth.getSecretKey(), encryptionSalt);
                 userRepository.saveUser(newUser);
                 ConsoleUtils.printSuccess("\nUsuário '" + username + "' configurado com sucesso!");
                 ConsoleUtils.printInfo("Por favor, execute o programa novamente para fazer login.");
                 isAuthenticated = false;
            } catch (SQLException e) {
                 ConsoleUtils.printError("Erro ao salvar o usuário no banco de dados: " + e.getMessage());
                 System.exit(1);
            }
        } else {
            ConsoleUtils.printError("Código 2FA inválido. Configuração falhou. Tente novamente.");
            setupFirstUser();
        }
    }

    /**
     * Autentica um usuário existente.
     * Gerencia login, verificação de senha mestra e 2FA.
     * Inicializa serviços e repositórios após autenticação bem-sucedida.
     */
    private void authenticateUser() {
        ConsoleUtils.printHeader("Autenticação de Usuário");

        String username = getStringInput("Nome de usuário: ");

        try {
            User userToAuthenticate = userRepository.findUserByUsername(username);

            if (userToAuthenticate == null) {
                ConsoleUtils.printError("Usuário não encontrado.");
                ConsoleUtils.printInfo("Deseja tentar outro nome de usuário (1) ou criar um novo usuário (2)?");
                int choice = getIntInput("Escolha uma opção: ");
                if (choice == 2) {
                    setupFirstUser();
                } else {
                     authenticateUser();
                }
                return;
            }

            String enteredPassword = getStringInput("Digite sua senha mestra: ");

            if (BCrypt.checkpw(enteredPassword, userToAuthenticate.getHashedPassword())) {
                ConsoleUtils.printSuccess("Senha mestra correta.");
                this.loggedInUser = userToAuthenticate;

                // Armazenar a senha mestra temporariamente para derivação da chave
                this.tempMasterPassword = enteredPassword;

                twoFactorAuth.setSecretKey(this.loggedInUser.getTwoFactorSecret());
                authenticate2FA();

                 // Se a autenticação 2FA for bem-sucedida, derivar a chave e inicializar serviços.
                 if (isAuthenticated) {
                      try {
                          SecretKey derivedKey = EncryptionService.deriveKey(this.tempMasterPassword, Base64.getDecoder().decode(loggedInUser.getEncryptionSalt()));
                          this.encryptionService = new EncryptionService(derivedKey);
                          this.credentialRepository = new DatabaseCredentialRepository(this.encryptionService);
                      } catch (Exception e) {
                           ConsoleUtils.printError("Erro durante a derivação da chave ou inicialização dos serviços: " + e.getMessage());
                           isAuthenticated = false;
                      }
                 }

            } else {
                ConsoleUtils.printError("Senha mestra incorreta.");
                 this.tempMasterPassword = null; // Limpar senha temporária
                authenticateUser();
            }
        } catch (SQLException e) {
            ConsoleUtils.printError("Erro de banco de dados durante a autenticação: " + e.getMessage());
            isAuthenticated = false;
        }
    }

    /**
     * Realiza a autenticação de dois fatores.
     */
    private void authenticate2FA() {
        ConsoleUtils.printHeader("Autenticação 2FA");
        String code = getValidatedInput("Digite o código do Google Authenticator: ", ValidationUtils::validate2FACode);

        if (twoFactorAuth.verifyCode(Integer.parseInt(code))) {
            isAuthenticated = true;
            ConsoleUtils.printSuccess("Autenticação 2FA bem-sucedida!");
        } else {
            ConsoleUtils.printError("Código 2FA inválido.");
            this.tempMasterPassword = null;
             ConsoleUtils.printError("Autenticação 2FA falhou.");
             isAuthenticated = false;
        }
    }

    /**
     * Exibe o menu principal.
     */
    private void showMenu() {
        ConsoleUtils.clearScreen();
        ConsoleUtils.printHeader(" MENU PRINCIPAL ");
        System.out.println();
        ConsoleUtils.printMenuOption(1, "Adicionar nova credencial");
        ConsoleUtils.printMenuOption(2, "Listar todas as credenciais");
        ConsoleUtils.printMenuOption(3, "Buscar credencial por serviço");
        ConsoleUtils.printMenuOption(4, "Gerar senha forte");
        ConsoleUtils.printMenuOption(5, "Verificar senha");
        ConsoleUtils.printMenuOption(6, "Sair");
        System.out.println();
        ConsoleUtils.printInfo("Use os números para selecionar uma opção.");
        ConsoleUtils.printDivider();
    }

    /**
     * Processa a escolha do usuário no menu principal.
     * @param choice A opção escolhida pelo usuário.
     */
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
        } finally {
             if (choice >= 1 && choice <= 5) {
                 ConsoleUtils.waitForEnter("Pressione Enter para continuar...");
             }
        }
    }

    /**
     * Adiciona uma nova credencial para o usuário logado.
     * @throws Exception se ocorrer um erro durante a adição ou criptografia.
     */
    private void addCredential() throws Exception {
        if (loggedInUser == null) {
            ConsoleUtils.printError("Nenhum usuário logado.");
            return;
        }

        ConsoleUtils.printHeader("Adicionar Nova Credencial");

        String service = getValidatedInput("Serviço: ", ValidationUtils::validateService);
        String email = getValidatedInput("Email: ", ValidationUtils::validateEmail);

        String password = ""; // Variável para armazenar a senha
        ConsoleUtils.printInfo("Deseja gerar uma senha forte (1) ou digitar manualmente (2)?");
        int passwordOption = getIntInput("Escolha uma opção (1 ou 2): ");

        if (passwordOption == 1) {
            // Gerar senha
            int length = getIntInput("Tamanho da senha (mínimo 8): ");
            while (length < 8) {
                ConsoleUtils.printError("Tamanho mínimo é 8 caracteres!");
                length = getIntInput("Tamanho da senha (mínimo 8): ");
            }
            password = encryptionService.generateStrongPassword(length);
            ConsoleUtils.printSuccess("Senha gerada: " + password);
        } else if (passwordOption == 2) {
            // Digitar manualmente
            password = getValidatedInput("Digite a senha: ", ValidationUtils::validatePassword);
        } else {
            ConsoleUtils.printError("Opção inválida. Cancelando adição de credencial.");
            return;
        }

        Credential newCredential = new Credential(service, email, password);

        try {
             credentialRepository.addCredential(loggedInUser.getUserId(), newCredential);
             ConsoleUtils.printSuccess("Credencial adicionada com sucesso!");
        } catch (SQLException e) {
             ConsoleUtils.printError("Erro ao salvar a credencial no banco de dados: " + e.getMessage());
        }
    }

    /**
     * Lista todas as credenciais para o usuário logado.
     */
    private void listCredentials() {
        if (loggedInUser == null) {
            ConsoleUtils.printError("Nenhum usuário logado.");
            return;
        }

        ConsoleUtils.printHeader("Credenciais");

        try {
             List<Credential> credentials = credentialRepository.findAllByUserId(loggedInUser.getUserId());
             if (credentials.isEmpty()) {
                 ConsoleUtils.printInfo("Nenhuma credencial cadastrada para este usuário.");
                 return;
             }

             for (Credential credential : credentials) {
                 ConsoleUtils.printDivider();
                  ConsoleUtils.printInfo(String.format("%sServiço: %s%s\n%sEmail: %s%s\n%sSenha: %s%s\n%sCriado em: %s%s\n%sÚltima atualização: %s%s\n%sStatus: %s%s",
                          ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                          credential.getService(), ConsoleUtils.RESET,
                          ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                          credential.getEmail(), ConsoleUtils.RESET,
                          ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                          credential.getPassword(), ConsoleUtils.RESET,
                           ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                           credential.getCreatedAt(), ConsoleUtils.RESET,
                           ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                          credential.getUpdatedAt(), ConsoleUtils.RESET,
                           ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                           credential.isCompromised() ? ConsoleUtils.RED + "COMPROMETIDO" : ConsoleUtils.GREEN + "Seguro", ConsoleUtils.RESET
                   ));
             }
        } catch (Exception e) {
            ConsoleUtils.printError("Erro ao listar credenciais do banco de dados: " + e.getMessage());
        }
    }

    /**
     * Busca credenciais por nome de serviço para o usuário logado.
     * (Nota: Implementação placeholder - atualmente lista todas as credenciais).
     */
    private void searchByService() {
         if (loggedInUser == null) {
             ConsoleUtils.printError("Nenhum usuário logado.");
             return;
         }

        ConsoleUtils.printHeader("Buscar por Serviço");
        String service = getValidatedInput("Nome do serviço: ", ValidationUtils::validateService);

        try {
             // TODO: Implementar busca por serviço no DatabaseCredentialRepository usando user_id
             ConsoleUtils.printWarning("Busca por serviço ainda não implementada para banco de dados. Exibindo todas as credenciais para o usuário logado como placeholder.");
             listCredentials(); // Código placeholder
        } catch (Exception e) {
            ConsoleUtils.printError("Erro ao buscar credenciais: " + e.getMessage());
        }
    }

    /**
     * Gera uma senha forte para o usuário.
     */
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

    /**
     * Verifica uma senha contra o banco de dados de vazamentos.
     */
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

     private String validateUsername(String username) {
         if (username == null || username.trim().isEmpty()) {
             return "O nome de usuário não pode estar vazio.";
         }
         return null;
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