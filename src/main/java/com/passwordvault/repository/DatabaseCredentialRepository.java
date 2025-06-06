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

    // TODO: Implementar findByService, updateCredential, removeCredential usando user_id
    // TODO: No findByService, buscar por service e user_id, depois descriptografar a senha antes de retornar.
} 