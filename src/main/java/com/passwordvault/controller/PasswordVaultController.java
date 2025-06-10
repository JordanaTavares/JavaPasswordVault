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

import com.passwordvault.repository.DatabaseCredentialRepository.DatabaseType;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.List;
import java.util.Scanner;
import java.util.Base64;
import java.util.Map;

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

    // Novo campo para rastrear o modo offline
    private boolean isOfflineMode = false; // Inicia no modo online por padrão

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
            while (true) { // Loop principal infinito
        if (!isAuthenticated) {
                    showInitialMenu();
                    int choice = getIntInput("Escolha uma opção: ");

                    switch (choice) {
                        case 1:
                            setupFirstUser();
                            break;
                        case 2:
                            authenticateUser();
                            break;
                        case 3:
                            ConsoleUtils.printInfo("Saindo...");
                            return; // Sai completamente do programa
                        default:
                            ConsoleUtils.printError("Opção inválida!");
                            break;
                    }
                } else {
            showMenu();
            int choice = getIntInput("Escolha uma opção: ");
            processChoice(choice);
        }
    }
        } catch (Exception e) {
            ConsoleUtils.printError("Ocorreu um erro inesperado durante a inicialização: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Exibe o menu inicial para criar usuário ou fazer login.
     */
    private void showInitialMenu() {
        ConsoleUtils.clearScreen();
        ConsoleUtils.printHeader("Gerenciador de Senhas Seguro");
        System.out.println();
        ConsoleUtils.printMenuOption(1, "Criar novo usuário");
        ConsoleUtils.printMenuOption(2, "Fazer login");
        ConsoleUtils.printMenuOption(3, "Sair");
        System.out.println();
        ConsoleUtils.printInfo("Use os números para selecionar uma opção.");
        ConsoleUtils.printDivider();
    }

    /**
     * Configura o primeiro usuário (usuário admin) se nenhum existir.
     * Este método foi generalizado para criar *qualquer* novo usuário.
     */
    private void setupFirstUser() {
        ConsoleUtils.printHeader("Configuração do Primeiro Usuário");

        while (true) {
            String username = getValidatedInput("Escolha um nome de usuário (ex: admin): ", this::validateUsername);
            
            try {
                // Verificar se o usuário já existe no banco local
                User existingUser = userRepository.findUserByUsername(username, DatabaseUserRepository.DatabaseType.LOCAL);
                if (existingUser != null) {
                    ConsoleUtils.printError("Este nome de usuário já está em uso!");
                    ConsoleUtils.printInfo("\nDeseja:");
                    ConsoleUtils.printMenuOption(1, "Tentar outro nome de usuário");
                    ConsoleUtils.printMenuOption(2, "Voltar ao menu principal");
                    
                    int choice = getIntInput("Escolha uma opção: ");
                    if (choice == 2) {
                        return;
                    }
                    continue; // Volta para pedir outro nome de usuário
                }

                // Verificar se o usuário já existe no banco remoto
                existingUser = userRepository.findUserByUsername(username, DatabaseUserRepository.DatabaseType.REMOTE);
                if (existingUser != null) {
                    ConsoleUtils.printError("Este nome de usuário já está em uso no banco remoto!");
                    ConsoleUtils.printInfo("\nDeseja:");
                    ConsoleUtils.printMenuOption(1, "Tentar outro nome de usuário");
                    ConsoleUtils.printMenuOption(2, "Voltar ao menu principal");
                    
                    int choice = getIntInput("Escolha uma opção: ");
                    if (choice == 2) {
                        return;
                    }
                    continue; // Volta para pedir outro nome de usuário
                }

                String masterPassword = getValidatedInput("Crie sua senha mestra: ", ValidationUtils::validatePassword);
                String confirmPassword = getStringInput("Confirme sua senha mestra: ");

                if (!masterPassword.equals(confirmPassword)) {
                    ConsoleUtils.printError("As senhas não coincidem!");
                    ConsoleUtils.printInfo("\nDeseja:");
                    ConsoleUtils.printMenuOption(1, "Tentar novamente");
                    ConsoleUtils.printMenuOption(2, "Voltar ao menu principal");
        
        int choice = getIntInput("Escolha uma opção: ");
                    if (choice == 2) {
                        return;
                    }
                    continue; // Volta para o início do processo
                }

                byte[] saltBytes = new byte[SALT_LENGTH];
                secureRandom.nextBytes(saltBytes);
                String encryptionSalt = Base64.getEncoder().encodeToString(saltBytes);

                ConsoleUtils.printInfo("\nVamos configurar a autenticação de dois fatores.");
                twoFactorAuth.setUsername(username);
                String qrCodeUrl = twoFactorAuth.generateNewSecretKey();
                ConsoleUtils.printInfo("Escaneie o QR Code com o Google Authenticator:");
                System.out.println(qrCodeUrl);
                String secretKey = twoFactorAuth.getSecretKey();
                ConsoleUtils.printWarning("Guarde esta chave secreta em um lugar seguro: " + secretKey);
                ConsoleUtils.printInfo("Após escanear o QR Code, aguarde alguns segundos para o código aparecer no aplicativo.");
                ConsoleUtils.printInfo("O código muda a cada 30 segundos.");

                int maxAttempts = 3;
                int attempts = 0;
                boolean verified = false;

                while (!verified && attempts < maxAttempts) {
                    String code = getValidatedInput("Digite o código do Google Authenticator: ", ValidationUtils::validate2FACode);
                    
                    // Limpar o código (remover espaços e caracteres não numéricos)
                    code = code.replaceAll("[^0-9]", "");
                    
                    try {
                        if (twoFactorAuth.verifyCode(Integer.parseInt(code))) {
                            verified = true;
                            try {
                                User newUser = new User(username, BCrypt.hashpw(masterPassword, BCrypt.gensalt()), secretKey, encryptionSalt);
                                
                                // Salvar no banco local
                                userRepository.saveUser(newUser, DatabaseUserRepository.DatabaseType.LOCAL);
                                ConsoleUtils.printSuccess("\nUsuário criado com sucesso no banco local!");
                                
                                // Salvar no banco remoto
                                try {
                                    userRepository.saveUser(newUser, DatabaseUserRepository.DatabaseType.REMOTE);
                                    ConsoleUtils.printSuccess("Usuário sincronizado com o banco remoto!");
                                } catch (Exception e) {
                                    ConsoleUtils.printWarning("Não foi possível salvar no banco remoto. O usuário será sincronizado posteriormente.");
                                    ConsoleUtils.printWarning("Erro: " + e.getMessage());
                                }
                                
                                this.loggedInUser = newUser;
                                SecretKey derivedKey = EncryptionService.deriveKey(masterPassword, Base64.getDecoder().decode(loggedInUser.getEncryptionSalt()));
                                this.encryptionService = new EncryptionService(derivedKey);
                                this.credentialRepository = new DatabaseCredentialRepository(this.encryptionService, this.userRepository);
                                
                                this.tempMasterPassword = null;
                                this.isAuthenticated = true;
                                return; // Sucesso! Sair do método
                            } catch (Exception e) {
                                ConsoleUtils.printError("Erro ao salvar o usuário ou inicializar serviços: " + e.getMessage());
                                ConsoleUtils.printInfo("\nDeseja:");
                                ConsoleUtils.printMenuOption(1, "Tentar novamente");
                                ConsoleUtils.printMenuOption(2, "Voltar ao menu principal");
                                
                                int choice = getIntInput("Escolha uma opção: ");
                                if (choice == 2) {
                                    return;
                                }
                                break; // Sai do loop de verificação 2FA e volta para o início
                            }
                        } else {
                            attempts++;
                            if (attempts < maxAttempts) {
                                ConsoleUtils.printError("Código 2FA inválido. Tentativas restantes: " + (maxAttempts - attempts));
                                ConsoleUtils.printInfo("Certifique-se de que o código está atualizado no aplicativo.");
                                ConsoleUtils.printInfo("Dica: O código muda a cada 30 segundos.");
        } else {
                                ConsoleUtils.printError("Número máximo de tentativas excedido.");
                                ConsoleUtils.printInfo("\nDeseja:");
                                ConsoleUtils.printMenuOption(1, "Tentar novamente");
                                ConsoleUtils.printMenuOption(2, "Voltar ao menu principal");
                                
                                int choice = getIntInput("Escolha uma opção: ");
                                if (choice == 2) {
                                    return;
                                }
                                break; // Sai do loop de verificação 2FA e volta para o início
                            }
                        }
                    } catch (NumberFormatException e) {
                        ConsoleUtils.printError("Código inválido. Digite apenas números.");
                        attempts++;
                    }
                }
            } catch (Exception e) {
                ConsoleUtils.printError("Erro durante a configuração do primeiro usuário: " + e.getMessage());
                ConsoleUtils.printInfo("\nDeseja:");
                ConsoleUtils.printMenuOption(1, "Tentar novamente");
                ConsoleUtils.printMenuOption(2, "Voltar ao menu principal");
                
                int choice = getIntInput("Escolha uma opção: ");
                if (choice == 2) {
                    return;
                }
                // Se escolher 1, continua no loop e tenta novamente
            }
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
            // Tentar encontrar o usuário primeiro no banco remoto
            User userToAuthenticate = userRepository.findUserByUsername(username, DatabaseUserRepository.DatabaseType.REMOTE);
            
            // Se não encontrar no remoto, tentar no local
            if (userToAuthenticate == null) {
                userToAuthenticate = userRepository.findUserByUsername(username, DatabaseUserRepository.DatabaseType.LOCAL);
                if (userToAuthenticate != null) {
                    isOfflineMode = true; // Ativar modo offline automaticamente
                    ConsoleUtils.printWarning("Usuário encontrado apenas no banco local. Ativando modo offline.");
                }
            }

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
                        this.credentialRepository = new DatabaseCredentialRepository(this.encryptionService, this.userRepository);
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
        } catch (Exception e) {
            ConsoleUtils.printError("Erro durante a autenticação: " + e.getMessage());
            if (e.getMessage().contains("Communications link failure")) {
                ConsoleUtils.printWarning("Problema de conexão com o banco remoto. Tentando modo offline...");
                isOfflineMode = true;
                authenticateUser(); // Tentar novamente em modo offline
            } else {
                isAuthenticated = false;
            }
        }
    }

    /**
     * Realiza a autenticação de dois fatores.
     */
    private void authenticate2FA() {
        ConsoleUtils.printHeader("Autenticação 2FA");
        
        int maxAttempts = 3;
        int attempts = 0;
        boolean verified = false;

        while (!verified && attempts < maxAttempts) {
            String code = getValidatedInput("Digite o código do Google Authenticator: ", ValidationUtils::validate2FACode);
            
            // Limpar o código (remover espaços e caracteres não numéricos)
            code = code.replaceAll("[^0-9]", "");
            
            try {
                if (twoFactorAuth.verifyCode(Integer.parseInt(code))) {
            isAuthenticated = true;
                    verified = true;
                    ConsoleUtils.printSuccess("Autenticação 2FA bem-sucedida!");
                } else {
                    attempts++;
                    if (attempts < maxAttempts) {
                        ConsoleUtils.printError("Código 2FA inválido. Tentativas restantes: " + (maxAttempts - attempts));
                        ConsoleUtils.printInfo("Certifique-se de que o código está atualizado no aplicativo.");
                        ConsoleUtils.printInfo("Dica: O código muda a cada 30 segundos.");
        } else {
                        ConsoleUtils.printError("Número máximo de tentativas excedido.");
                        this.tempMasterPassword = null;
                        ConsoleUtils.printError("Autenticação 2FA falhou.");
                        isAuthenticated = false;
                    }
                }
            } catch (NumberFormatException e) {
                ConsoleUtils.printError("Código inválido. Digite apenas números.");
                attempts++;
            }
        }
    }

    /**
     * Exibe o menu principal.
     */
    private void showMenu() {
        ConsoleUtils.clearScreen();
        ConsoleUtils.printHeader(" MENU PRINCIPAL ");
        
        // Mostrar informações do usuário logado e modo atual
        System.out.println();
        ConsoleUtils.printInfo("Usuário: " + ConsoleUtils.BOLD + ConsoleUtils.GREEN + loggedInUser.getUsername() + ConsoleUtils.RESET);
        ConsoleUtils.printInfo("Modo: " + (isOfflineMode ? ConsoleUtils.RED + "Offline" : ConsoleUtils.GREEN + "Online") + ConsoleUtils.RESET);
        
        System.out.println();
        ConsoleUtils.printMenuOption(1, "Adicionar nova credencial");
        ConsoleUtils.printMenuOption(2, "Listar todas as credenciais");
        ConsoleUtils.printMenuOption(3, "Buscar credencial por serviço");
        ConsoleUtils.printMenuOption(4, "Gerar senha forte");
        ConsoleUtils.printMenuOption(5, "Verificar senha");
        ConsoleUtils.printMenuOption(6, "Modo Offline / Sincronização");
        ConsoleUtils.printMenuOption(7, "Ver detalhes do usuário");
        ConsoleUtils.printMenuOption(8, "Sair");
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
                case 6 -> handleSyncOptions();
                case 7 -> showUserDetails();
                case 8 -> {
                    isAuthenticated = false;
                    ConsoleUtils.printInfo("Saindo...");
                }
                default -> ConsoleUtils.printError("Opção inválida!");
            }
        } catch (Exception e) {
            ConsoleUtils.printError("Erro: " + e.getMessage());
        } finally {
             if (choice >= 1 && choice <= 7) { // Opções 1-7 são operações que podem precisar de pausa
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

        // Determinar qual repositório usar (local ou remoto)
        DatabaseCredentialRepository currentCredentialRepository = this.credentialRepository;
        DatabaseType currentDbType = isOfflineMode ? DatabaseType.LOCAL : DatabaseType.REMOTE;

        if (currentCredentialRepository == null) {
            ConsoleUtils.printError("Repositório de credenciais não inicializado.");
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
             // Usar o repositório determinado (local ou remoto)
             currentCredentialRepository.addCredential(loggedInUser.getUserId(), newCredential, currentDbType);
             ConsoleUtils.printSuccess("Credencial adicionada com sucesso!");
        } catch (Exception e) {
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

        // Determinar qual repositório usar (local ou remoto)
        DatabaseCredentialRepository currentCredentialRepository = this.credentialRepository;
        DatabaseType currentDbType = isOfflineMode ? DatabaseType.LOCAL : DatabaseType.REMOTE;

        if (currentCredentialRepository == null) {
            ConsoleUtils.printError("Repositório de credenciais não inicializado.");
            return;
        }

        ConsoleUtils.printHeader("Credenciais");

        try {
             // Usar o repositório determinado (local ou remoto)
             List<Credential> credentials = currentCredentialRepository.findAllByUserId(loggedInUser.getUserId(), currentDbType);
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

        // Determinar qual repositório usar (local ou remoto)
        DatabaseCredentialRepository currentCredentialRepository = this.credentialRepository;
        DatabaseType currentDbType = isOfflineMode ? DatabaseType.LOCAL : DatabaseType.REMOTE;

        if (currentCredentialRepository == null) {
            ConsoleUtils.printError("Repositório de credenciais não inicializado.");
            return;
        }

        ConsoleUtils.printHeader("Buscar por Serviço");
        String service = getValidatedInput("Nome do serviço: ", ValidationUtils::validateService);

        try {

              // Usar o repositório determinado (local ou remoto)
              List<Credential> credentials = currentCredentialRepository.findByUserIdAndService(loggedInUser.getUserId(), service, currentDbType);

              if (credentials.isEmpty()) {
                  ConsoleUtils.printInfo("Nenhuma credencial encontrada para o serviço: " + service);
                  return;
              }

              ConsoleUtils.printInfo("Credenciais encontradas para o serviço: " + service);
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

    /**
     * Método placeholder para lidar com as opções de modo offline e sincronização.
     */
    private void handleSyncOptions() {
        ConsoleUtils.printHeader("Modo Offline / Sincronização");
        // ConsoleUtils.printInfo("TODO: Implementar lógica de modo offline e sincronização aqui.");
        // Aqui no futuro adicionaremos sub-opções como:
        // 1. Sincronizar agora
        // 2. Configurar sincronização
        // 3. Ativar/Desativar modo offline
        // ...

        boolean exitSyncMenu = false;
        while (!exitSyncMenu) {
            showSyncMenu();
            int choice = getIntInput("Escolha uma opção: ");

            switch (choice) {
                case 1:
                    performSync(); // Lógica de sincronização
                    break;
                case 2:
                    configureSync(); // Configuração da sincronização
                    break;
                case 3:
                    toggleOfflineMode(); // Novo método para alternar modo offline
                    break;
                case 4:
                    ConsoleUtils.printInfo("Voltando para o Menu Principal...");
                    exitSyncMenu = true;
                    break;
                default:
                    ConsoleUtils.printError("Opção inválida!");
                    break;
            }
             if (!exitSyncMenu) { // Pausar apenas se não estiver saindo do sub-menu
                 ConsoleUtils.waitForEnter("Pressione Enter para continuar...");
             }
        }
    }

    /**
     * Exibe o sub-menu para opções de modo offline e sincronização.
     */
    private void showSyncMenu() {
        ConsoleUtils.clearScreen();
        ConsoleUtils.printHeader("Sincronização e Offline");
        System.out.println();
        ConsoleUtils.printMenuOption(1, "Sincronizar agora");
        ConsoleUtils.printMenuOption(2, "Configurar sincronização");
        ConsoleUtils.printMenuOption(3, "Ativar/Desativar modo offline");
        ConsoleUtils.printMenuOption(4, "Voltar");
        System.out.println();
        ConsoleUtils.printInfo("Use os números para selecionar uma opção.");
        ConsoleUtils.printDivider();
    }

    /**
     * Realiza a sincronização entre o banco local e remoto.
     */
    private void performSync() {
        ConsoleUtils.printHeader("Sincronizar Agora");
        
        if (loggedInUser == null) {
            ConsoleUtils.printError("Nenhum usuário logado.");
            return;
        }

        try {
            ConsoleUtils.printInfo("Iniciando sincronização...");
            // Sincronizar apenas o usuário atual
            Map<String, Integer> currentUserMap = userRepository.syncSingleUser(loggedInUser);
            
            // Sincronizar apenas as credenciais do usuário atual
            credentialRepository.syncCredentials(loggedInUser.getUserId(), currentUserMap);
            ConsoleUtils.printSuccess("Sincronização concluída com sucesso!");
        } catch (Exception e) {
            ConsoleUtils.printError("Erro durante a sincronização: " + e.getMessage());
        }
    }

    /**
     * Método para configuração de sincronização.
     */
    private void configureSync() {
        ConsoleUtils.printHeader("Configurar Sincronização");
        ConsoleUtils.printInfo("Esta funcionalidade será implementada em versões futuras.");
    }

    /**
     * Alterna entre modo online e offline.
     */
    private void toggleOfflineMode() {
        isOfflineMode = !isOfflineMode;
        ConsoleUtils.printSuccess("Modo Offline: " + (isOfflineMode ? ConsoleUtils.GREEN + "ATIVADO" : ConsoleUtils.RED + "DESATIVADO") + ConsoleUtils.RESET);
    }

    /**
     * Mostra os detalhes do usuário atual.
     */
    private void showUserDetails() {
        ConsoleUtils.printHeader("Detalhes do Usuário");
        
        ConsoleUtils.printInfo(String.format("%sID: %s%d%s",
            ConsoleUtils.BOLD + ConsoleUtils.CYAN,
            ConsoleUtils.GREEN,
            loggedInUser.getUserId(),
            ConsoleUtils.RESET));
            
        ConsoleUtils.printInfo(String.format("%sNome de usuário: %s%s%s",
            ConsoleUtils.BOLD + ConsoleUtils.CYAN,
            ConsoleUtils.GREEN,
            loggedInUser.getUsername(),
            ConsoleUtils.RESET));
            
        ConsoleUtils.printInfo(String.format("%sChave 2FA: %s%s%s",
            ConsoleUtils.BOLD + ConsoleUtils.CYAN,
            ConsoleUtils.GREEN,
            loggedInUser.getTwoFactorSecret(),
            ConsoleUtils.RESET));
            
        ConsoleUtils.printWarning("\nIMPORTANTE: Mantenha sua chave 2FA em um local seguro!");
        
        try {
            // Buscar quantidade de credenciais
            DatabaseType currentDbType = isOfflineMode ? DatabaseType.LOCAL : DatabaseType.REMOTE;
            List<Credential> credentials = credentialRepository.findAllByUserId(loggedInUser.getUserId(), currentDbType);
            
            ConsoleUtils.printInfo(String.format("%sTotal de credenciais: %s%d%s",
                ConsoleUtils.BOLD + ConsoleUtils.CYAN,
                ConsoleUtils.GREEN,
                credentials.size(),
                ConsoleUtils.RESET));
                
            // Contar credenciais comprometidas
            long compromisedCount = credentials.stream().filter(Credential::isCompromised).count();
            if (compromisedCount > 0) {
                ConsoleUtils.printWarning(String.format("Credenciais comprometidas: %d", compromisedCount));
            }
        } catch (Exception e) {
            ConsoleUtils.printError("Erro ao buscar credenciais: " + e.getMessage());
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