package com.passwordvault.repository;

import com.passwordvault.model.Credential;
import com.passwordvault.security.EncryptionService;
import com.passwordvault.utils.PropertyLoader;
import com.passwordvault.utils.DatabaseConnectionManager;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Map;
import java.util.stream.Collectors;

public class DatabaseCredentialRepository {
    private final EncryptionService encryptionService;
    private final DatabaseUserRepository userRepository;

    public DatabaseCredentialRepository(EncryptionService encryptionService, DatabaseUserRepository userRepository) {
        this.encryptionService = encryptionService;
        this.userRepository = userRepository;
    }

    // Enum para indicar qual banco de dados usar (copiado de UserRepository)
    public enum DatabaseType {
        LOCAL,
        REMOTE
    }

    private Connection getConnection(DatabaseType type) throws SQLException {
        String dbUrl;
        String dbUser;
        String dbPassword;

        if (type == DatabaseType.LOCAL) {
            dbUrl = PropertyLoader.getDbLocalUrl();
            dbUser = PropertyLoader.getDbLocalUser();
            dbPassword = PropertyLoader.getDbLocalPassword();

            if (dbUrl == null) {
                throw new SQLException("Configuração do banco de dados local (db.local.url) não encontrada.");
            }
            // Para SQLite, a URL deve ser algo como jdbc:sqlite:/caminho/para/seu/arquivo.db
            // As propriedades do MySQL 8+ não são necessárias.

        } else { // Default para REMOTE
            dbUrl = PropertyLoader.getDbRemoteUrl();
            dbUser = PropertyLoader.getDbRemoteUser();
            dbPassword = PropertyLoader.getDbRemotePassword();

            if (dbUrl == null || dbUser == null || dbPassword == null) {
                throw new SQLException("Configurações do banco de dados remoto (db.url, db.user, db.password) não encontradas no application.properties.");
            }

            // Adicionar propriedades de conexão necessárias para MySQL 8+ (apenas para REMOTO)
            if (!dbUrl.contains("?")) {
                dbUrl += "?";
            } else {
                dbUrl += "&";
            }
            dbUrl += "allowPublicKeyRetrieval=true&useSSL=false";
        }

        return DatabaseConnectionManager.getInstance().getConnection(dbUrl, dbUser, dbPassword);
    }

    // Adicionar método para fechar conexão
    private void closeConnection(Connection conn) {
        if (conn != null) {
            DatabaseConnectionManager.getInstance().closeConnection(conn);
        }
    }

    /**
     * Adiciona uma nova credencial ao banco de dados para um usuário específico.
     * Assume que o objeto Credential contém a senha pura (não criptografada).
     * @param userId O ID do usuário proprietário da credencial.
     * @param credential A credencial a ser adicionada (com senha pura).
     * @param type O tipo de banco de dados a ser usado.
     * @throws SQLException se ocorrer um erro de banco de dados.
     * @throws Exception se ocorrer um erro durante a criptografia.
     */
    public void addCredential(int userId, Credential credential, DatabaseType type) throws SQLException, Exception {
        Connection conn = null;
        try {
            conn = getConnection(type);
            String sql = "INSERT INTO credentials (user_id, id, service, email, encrypted_password, created_at, updated_at, is_compromised) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                String encryptedPassword = encryptionService.encrypt(credential.getPassword());

                pstmt.setInt(1, userId);
                pstmt.setString(2, credential.getId().toString());
                pstmt.setString(3, credential.getService());
                pstmt.setString(4, credential.getEmail());
                pstmt.setString(5, encryptedPassword);
                pstmt.setTimestamp(6, Timestamp.valueOf(credential.getCreatedAt()));
                pstmt.setTimestamp(7, Timestamp.valueOf(credential.getUpdatedAt()));
                pstmt.setBoolean(8, credential.isCompromised());

                pstmt.executeUpdate();

                try (ResultSet generatedKeys = pstmt.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        credential.setCredentialId(generatedKeys.getInt(1));
                    }
                }
            }
        } finally {
            closeConnection(conn);
        }
    }

     /**
     * Busca todas as credenciais para um usuário específico.
     * @param userId O ID do usuário cujas credenciais serão buscadas.
     * @param type O tipo de banco de dados a ser usado.
     * @return Uma lista de credenciais (com senhas descriptografadas).
     * @throws SQLException se ocorrer um erro de banco de dados.
     * @throws Exception se ocorrer um erro durante a descriptografia.
     */
    public List<Credential> findAllByUserId(int userId, DatabaseType type) throws SQLException, Exception {
        Connection conn = null;
        try {
            conn = getConnection(type);
            List<Credential> credentials = new ArrayList<>();
            String sql = "SELECT credential_id, id, service, email, encrypted_password, created_at, updated_at, is_compromised FROM credentials WHERE user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setInt(1, userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        int credentialId = rs.getInt("credential_id");
                        UUID id = UUID.fromString(rs.getString("id"));
                        String service = rs.getString("service");
                        String email = rs.getString("email");
                        String encryptedPassword = rs.getString("encrypted_password");
                        LocalDateTime createdAt = rs.getTimestamp("created_at").toLocalDateTime();
                        LocalDateTime updatedAt = rs.getTimestamp("updated_at").toLocalDateTime();
                        boolean isCompromised = rs.getBoolean("is_compromised");

                        String decryptedPassword = encryptionService.decrypt(encryptedPassword);

                        Credential credential = new Credential(credentialId, id, service, email, decryptedPassword, createdAt, updatedAt, isCompromised, userId);
                        credentials.add(credential);
                    }
                }
            }
            return credentials;
        } finally {
            closeConnection(conn);
        }
    }

    /**
     * Busca credenciais por nome de serviço para um usuário específico.
     * @param userId O ID do usuário proprietário da credencial.
     * @param service O nome do serviço a ser buscado.
     * @param type O tipo de banco de dados a ser usado.
     * @return Uma lista de credenciais (com senhas descriptografadas) que correspondem ao serviço.
     * @throws SQLException se ocorrer um erro de banco de dados.
     * @throws Exception se ocorrer um erro durante a descriptografia.
     */
    public List<Credential> findByUserIdAndService(int userId, String service, DatabaseType type) throws SQLException, Exception {
        Connection conn = null;
        try {
            conn = getConnection(type);
            List<Credential> credentials = new ArrayList<>();
            String sql = "SELECT credential_id, id, service, email, encrypted_password, created_at, updated_at, is_compromised FROM credentials WHERE user_id = ? AND service = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setInt(1, userId);
                pstmt.setString(2, service);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        int credentialId = rs.getInt("credential_id");
                        UUID id = UUID.fromString(rs.getString("id"));
                        String dbService = rs.getString("service");
                        String email = rs.getString("email");
                        String encryptedPassword = rs.getString("encrypted_password");
                        LocalDateTime createdAt = rs.getTimestamp("created_at").toLocalDateTime();
                        LocalDateTime updatedAt = rs.getTimestamp("updated_at").toLocalDateTime();
                        boolean isCompromised = rs.getBoolean("is_compromised");

                        String decryptedPassword = encryptionService.decrypt(encryptedPassword);

                        Credential credential = new Credential(credentialId, id, dbService, email, decryptedPassword, createdAt, updatedAt, isCompromised, userId);
                        credentials.add(credential);
                    }
                }
            }
            return credentials;
        } finally {
            closeConnection(conn);
        }
    }

    /**
     * Atualiza uma credencial existente no banco de dados para um usuário específico.
     * @param userId O ID do usuário proprietário da credencial.
     * @param credential A credencial a ser atualizada (com dados atualizados).
     * @param type O tipo de banco de dados a ser usado.
     * @throws SQLException se ocorrer um erro de banco de dados.
     * @throws Exception se ocorrer um erro durante a criptografia.
     */
    public void updateCredential(int userId, Credential credential, DatabaseType type) throws SQLException, Exception {
        Connection conn = null;
        try {
            conn = getConnection(type);
            String sql = "UPDATE credentials SET service = ?, email = ?, encrypted_password = ?, updated_at = ?, is_compromised = ? WHERE credential_id = ? AND user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                String encryptedPassword = encryptionService.encrypt(credential.getPassword());

                pstmt.setString(1, credential.getService());
                pstmt.setString(2, credential.getEmail());
                pstmt.setString(3, encryptedPassword);
                pstmt.setTimestamp(4, Timestamp.valueOf(LocalDateTime.now()));
                pstmt.setBoolean(5, credential.isCompromised());
                pstmt.setInt(6, credential.getCredentialId());
                pstmt.setInt(7, userId);

                int affectedRows = pstmt.executeUpdate();
                if (affectedRows == 0) {
                    throw new SQLException("Falha ao atualizar credencial, credencial não encontrada ou não pertence ao usuário.");
                }
                credential.setUpdatedAt(LocalDateTime.now());
            }
        } finally {
            closeConnection(conn);
        }
    }

    /**
     * Remove uma credencial do banco de dados para um usuário específico.
     * @param userId O ID do usuário proprietário da credencial.
     * @param credentialId O ID da credencial a ser removida.
     * @param type O tipo de banco de dados a ser usado.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public void removeCredential(int userId, int credentialId, DatabaseType type) throws SQLException {
        Connection conn = null;
        try {
            conn = getConnection(type);
            String sql = "DELETE FROM credentials WHERE credential_id = ? AND user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setInt(1, credentialId);
                pstmt.setInt(2, userId);

                int affectedRows = pstmt.executeUpdate();
                if (affectedRows == 0) {
                    throw new SQLException("Falha ao remover credencial, credencial não encontrada ou não pertence ao usuário.");
                }
            }
        } finally {
            closeConnection(conn);
        }
    }

    /**
     * Sincroniza as credenciais entre o banco local e remoto para um usuário específico.
     * @param userId O ID do usuário cujas credenciais serão sincronizadas.
     * @param localUserIds Um mapa de user_id local para facilitar a sincronização
     * @throws SQLException se ocorrer um erro de banco de dados.
     * @throws Exception se ocorrer um erro durante a criptografia.
     */
    public void syncCredentials(int userId, Map<String, Integer> localUserIds) throws SQLException, Exception {
        Connection conn = null;
        try {
            conn = getConnection(DatabaseType.REMOTE);
            // Buscar credenciais do banco remoto (ainda precisamos do userId remoto para buscar)
            List<Credential> remoteCredentials = findAllByUserId(userId, DatabaseType.REMOTE);

            // Buscar credenciais do banco local
            List<Credential> localCredentials = new ArrayList<>();
            // Consulta SQL para buscar credenciais do banco local
            String sql = "SELECT credential_id, id, service, email, encrypted_password, created_at, updated_at, is_compromised, user_id FROM credentials WHERE user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                // Precisamos obter o user_id local correspondente ao userId remoto que foi passado
                // Assumimos que userId (parâmetro do método) é o ID remoto.
                // Vamos encontrar o username do usuário remoto e depois o user_id local.
                String username = userRepository.findUsernameByUserId(userId, DatabaseUserRepository.DatabaseType.REMOTE);
                Integer localUserIdForQuery = localUserIds.get(username);

                if (localUserIdForQuery == null) { // Isso não deve acontecer se syncUsers rodou primeiro e o usuário existe localmente
                    System.err.println("Erro interno na sincronização: User ID local não encontrado para o username " + username + " (remote ID: " + userId + ").");
                    return; // Aborta a sincronização de credenciais para este usuário
                }

                pstmt.setInt(1, localUserIdForQuery); // Usar o ID do usuário local para buscar credenciais locais
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        int credentialId = rs.getInt("credential_id");
                        UUID id = UUID.fromString(rs.getString("id"));
                        String service = rs.getString("service");
                        String email = rs.getString("email");
                        String encryptedPassword = rs.getString("encrypted_password");
                        LocalDateTime createdAt = rs.getTimestamp("created_at").toLocalDateTime();
                        LocalDateTime updatedAt = rs.getTimestamp("updated_at").toLocalDateTime();
                        boolean isCompromised = rs.getBoolean("is_compromised");
                        int credUserId = rs.getInt("user_id"); // Obter o user_id da credencial local

                        String decryptedPassword = encryptionService.decrypt(encryptedPassword);
                        // Ao criar o objeto Credential local, usamos o credUserId lido do banco de dados local
                        Credential credential = new Credential(credentialId, id, service, email, decryptedPassword, createdAt, updatedAt, isCompromised, credUserId);
                        localCredentials.add(credential);
                    }
                }
            }

            // Criar mapas para facilitar a busca por UUID
            Map<UUID, Credential> remoteMap = remoteCredentials.stream()
                .collect(Collectors.toMap(Credential::getId, c -> c));
            Map<UUID, Credential> localMap = localCredentials.stream()
                .collect(Collectors.toMap(Credential::getId, c -> c));

            // Sincronizar do remoto para o local
            for (Credential remoteCred : remoteCredentials) {
                Credential localCred = localMap.get(remoteCred.getId());
                // Obter o ID de usuário local correspondente para esta credencial remota
                String username = userRepository.findUsernameByUserId(remoteCred.getUserId(), DatabaseUserRepository.DatabaseType.REMOTE);
                Integer localUserIdForCred = localUserIds.get(username);
                
                if (localUserIdForCred == null) { // Isso não deve acontecer se syncUsers rodou primeiro e o usuário existe localmente
                    System.err.println("Erro interno na sincronização: User ID local não encontrado para o username " + username + " (remote ID: " + remoteCred.getUserId() + ").");
                    continue; // Pula esta credencial
                }

                if (localCred == null) {
                    // Credencial existe apenas no remoto - adicionar ao local com o ID de usuário local correto
                    System.out.println("Sincronizando credencial remota para local (adicionar): " + remoteCred.getService() + " para usuário local ID " + localUserIdForCred);
                    // Antes de adicionar ao local, definimos o user_id da credencial para o ID local correspondente
                    remoteCred.setUserId(localUserIdForCred); 
                    addCredential(localUserIdForCred, remoteCred, DatabaseType.LOCAL); // Usar localUserIdForCred aqui
                } else if (remoteCred.getUpdatedAt().isAfter(localCred.getUpdatedAt())) {
                    // Credencial remota é mais recente - atualizar local com o ID de usuário local correto
                    System.out.println("Sincronizando credencial remota para local (atualizar): " + remoteCred.getService() + " para usuário local ID " + localUserIdForCred);
                    // Antes de atualizar no local, definimos o user_id da credencial para o ID local correspondente
                    remoteCred.setUserId(localUserIdForCred);
                    updateCredential(localUserIdForCred, remoteCred, DatabaseType.LOCAL); // Usar localUserIdForCred aqui e credencial com ID local
                }
            }

            // Sincronizar do local para o remoto
            // Nota: Esta parte da sincronização pressupõe que o usuário já existe remotamente.
            // Se um usuário for criado offline e adicionarmos credenciais antes de sincronizar usuários,
            // precisaremos ajustar a lógica para adicionar o usuário remoto primeiro e então as credenciais associadas.
            for (Credential localCred : localCredentials) {
                Credential remoteCred = remoteMap.get(localCred.getId());
                // Ao sincronizar do local para o remoto, o user_id na credencial local já deve ser o ID remoto correto (obtido no login ou primeira sincronização)
                // Não precisamos de localUserIds aqui, pois estamos escrevendo para o banco remoto.

                if (remoteCred == null) {
                    // Credencial existe apenas no local - adicionar ao remoto usando o user_id remoto da credencial local
                    System.out.println("Sincronizando credencial local para remoto (adicionar): " + localCred.getService() + " para usuário remoto ID " + localCred.getUserId());
                    addCredential(localCred.getUserId(), localCred, DatabaseType.REMOTE); // Usar localCred.getUserId() (ID remoto) aqui
                } else if (localCred.getUpdatedAt().isAfter(remoteCred.getUpdatedAt())) {
                    // Credencial local é mais recente - atualizar remoto usando o user_id remoto da credencial local
                    System.out.println("Sincronizando credencial local para remoto (atualizar): " + localCred.getService() + " para usuário remoto ID " + localCred.getUserId());
                    updateCredential(localCred.getUserId(), localCred, DatabaseType.REMOTE); // Usar localCred.getUserId() (ID remoto) aqui
                }
            }
        } finally {
            closeConnection(conn);
        }
    }
} 