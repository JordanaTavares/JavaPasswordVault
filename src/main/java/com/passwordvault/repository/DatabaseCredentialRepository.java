package com.passwordvault.repository;

import com.passwordvault.model.Credential;
import com.passwordvault.security.EncryptionService;
import com.passwordvault.utils.PropertyLoader;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class DatabaseCredentialRepository {
    private final EncryptionService encryptionService;

    public DatabaseCredentialRepository(EncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    private Connection getConnection() throws SQLException {
        String dbUrl = PropertyLoader.getProperty("db.url");
        String dbUser = PropertyLoader.getProperty("db.user");
        String dbPassword = PropertyLoader.getProperty("db.password");

        if (dbUrl == null || dbUser == null || dbPassword == null) {
            throw new SQLException("Configurações do banco de dados (db.url, db.user, db.password) não encontradas no application.properties.");
        }

        if (!dbUrl.contains("?")) {
            dbUrl += "?";
        } else {
            dbUrl += "&";
        }
        dbUrl += "allowPublicKeyRetrieval=true&useSSL=false";

        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }

    /**
     * Adiciona uma nova credencial ao banco de dados para um usuário específico.
     * Assume que o objeto Credential contém a senha pura (não criptografada).
     * @param userId O ID do usuário proprietário da credencial.
     * @param credential A credencial a ser adicionada (com senha pura).
     * @throws SQLException se ocorrer um erro de banco de dados.
     * @throws Exception se ocorrer um erro durante a criptografia.
     */
    public void addCredential(int userId, Credential credential) throws SQLException, Exception {
        String sql = "INSERT INTO credentials (user_id, id, service, email, encrypted_password, created_at, updated_at, is_compromised) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            String encryptedPassword = encryptionService.encrypt(credential.getPassword());

            pstmt.setInt(1, userId);
            pstmt.setString(2, credential.getId().toString()); // Salvar UUID como String
            pstmt.setString(3, credential.getService());
            pstmt.setString(4, credential.getEmail());
            pstmt.setString(5, encryptedPassword); // Salvar senha criptografada
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
    }

     /**
     * Busca todas as credenciais para um usuário específico.
     * @param userId O ID do usuário cujas credenciais serão buscadas.
     * @return Uma lista de credenciais (com senhas descriptografadas).
     * @throws SQLException se ocorrer um erro de banco de dados.
     * @throws Exception se ocorrer um erro durante a descriptografia.
     */
    public List<Credential> findAllByUserId(int userId) throws SQLException, Exception {
        List<Credential> credentials = new ArrayList<>();
        String sql = "SELECT credential_id, id, service, email, encrypted_password, created_at, updated_at, is_compromised FROM credentials WHERE user_id = ?";
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    int credentialId = rs.getInt("credential_id");
                    UUID id = UUID.fromString(rs.getString("id")); // Ler UUID como String
                    String service = rs.getString("service");
                    String email = rs.getString("email");
                    String encryptedPassword = rs.getString("encrypted_password");
                    LocalDateTime createdAt = rs.getTimestamp("created_at").toLocalDateTime();
                    LocalDateTime updatedAt = rs.getTimestamp("updated_at").toLocalDateTime();
                    boolean isCompromised = rs.getBoolean("is_compromised");

                    String decryptedPassword = encryptionService.decrypt(encryptedPassword);

                    Credential credential = new Credential(credentialId, id, service, email, decryptedPassword, createdAt, updatedAt, isCompromised);
                    credentials.add(credential);
                }
            }
        }
        return credentials;
    }

    /**
     * Busca credenciais por nome de serviço para um usuário específico.
     * @param userId O ID do usuário proprietário da credencial.
     * @param service O nome do serviço a ser buscado.
     * @return Uma lista de credenciais (com senhas descriptografadas) que correspondem ao serviço.
     * @throws SQLException se ocorrer um erro de banco de dados.
     * @throws Exception se ocorrer um erro durante a descriptografia.
     */
    public List<Credential> findByUserIdAndService(int userId, String service) throws SQLException, Exception {
        List<Credential> credentials = new ArrayList<>();
        // Consulta SQL para buscar credenciais pelo user_id e service
        String sql = "SELECT credential_id, id, service, email, encrypted_password, created_at, updated_at, is_compromised FROM credentials WHERE user_id = ? AND service = ?";
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, userId);
            pstmt.setString(2, service);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    int credentialId = rs.getInt("credential_id");
                    UUID id = UUID.fromString(rs.getString("id")); // Ler UUID como String
                    String dbService = rs.getString("service");
                    String email = rs.getString("email");
                    String encryptedPassword = rs.getString("encrypted_password");
                    LocalDateTime createdAt = rs.getTimestamp("created_at").toLocalDateTime();
                    LocalDateTime updatedAt = rs.getTimestamp("updated_at").toLocalDateTime();
                    boolean isCompromised = rs.getBoolean("is_compromised");

                    String decryptedPassword = encryptionService.decrypt(encryptedPassword);

                    Credential credential = new Credential(credentialId, id, dbService, email, decryptedPassword, createdAt, updatedAt, isCompromised);
                    credentials.add(credential);
                }
            }
        }
        return credentials;
    }

    /**
     * Atualiza uma credencial existente no banco de dados para um usuário específico.
     * @param userId O ID do usuário proprietário da credencial.
     * @param credential A credencial a ser atualizada (com dados atualizados).
     * @throws SQLException se ocorrer um erro de banco de dados.
     * @throws Exception se ocorrer um erro durante a criptografia.
     */
    public void updateCredential(int userId, Credential credential) throws SQLException, Exception {
        String sql = "UPDATE credentials SET service = ?, email = ?, encrypted_password = ?, updated_at = ?, is_compromised = ? WHERE credential_id = ? AND user_id = ?";
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            String encryptedPassword = encryptionService.encrypt(credential.getPassword());

            pstmt.setString(1, credential.getService());
            pstmt.setString(2, credential.getEmail());
            pstmt.setString(3, encryptedPassword); // Salvar senha criptografada
            pstmt.setTimestamp(4, Timestamp.valueOf(LocalDateTime.now())); // Atualizar updated_at
            pstmt.setBoolean(5, credential.isCompromised());
            pstmt.setInt(6, credential.getCredentialId());
            pstmt.setInt(7, userId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                 throw new SQLException("Falha ao atualizar credencial, credencial não encontrada ou não pertence ao usuário.");
            }
             credential.setUpdatedAt(LocalDateTime.now()); // Atualizar objeto em memória também
        }
    }

    /**
     * Remove uma credencial do banco de dados para um usuário específico.
     * @param userId O ID do usuário proprietário da credencial.
     * @param credentialId O ID da credencial a ser removida.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public void removeCredential(int userId, int credentialId) throws SQLException {
        String sql = "DELETE FROM credentials WHERE credential_id = ? AND user_id = ?";
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, credentialId);
            pstmt.setInt(2, userId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                 throw new SQLException("Falha ao remover credencial, credencial não encontrada ou não pertence ao usuário.");
            }
        }
    }
} 