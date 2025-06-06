package com.passwordvault.repository;

import com.passwordvault.model.User;
import com.passwordvault.utils.PropertyLoader;
import java.sql.*;

public class DatabaseUserRepository {
    private Connection getConnection() throws SQLException {
        String dbUrl = PropertyLoader.getProperty("db.url");
        String dbUser = PropertyLoader.getProperty("db.user");
        String dbPassword = PropertyLoader.getProperty("db.password");

        if (dbUrl == null || dbUser == null || dbPassword == null) {
            throw new SQLException("Configurações do banco de dados (db.url, db.user, db.password) não encontradas no application.properties.");
        }

        // Adicionar propriedades de conexão necessárias para MySQL 8+
        if (!dbUrl.contains("?")) {
            dbUrl += "?";
        } else {
            dbUrl += "&";
        }
        dbUrl += "allowPublicKeyRetrieval=true&useSSL=false";

        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }

    /**
     * Salva um novo usuário no banco de dados.
     * @param user O objeto User a ser salvo.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public void saveUser(User user) throws SQLException {
        String sql = "INSERT INTO users (username, hashedPassword, twoFactorSecret, encryptionSalt) VALUES (?, ?, ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, user.getUsername());
            pstmt.setString(2, user.getHashedPassword());
            pstmt.setString(3, user.getTwoFactorSecret());
            pstmt.setString(4, user.getEncryptionSalt());
            pstmt.executeUpdate();

            try (ResultSet generatedKeys = pstmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    user.setUserId(generatedKeys.getInt(1));
                }
            }
        }
    }

    /**
     * Encontra um usuário pelo nome de usuário.
     * @param username O nome de usuário a ser buscado.
     * @return O objeto User encontrado, ou null se não existir.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public User findUserByUsername(String username) throws SQLException {
        String sql = "SELECT user_id, username, hashed_password, two_factor_secret, encryption_salt FROM users WHERE username = ?";
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    int userId = rs.getInt("user_id");
                    String dbUsername = rs.getString("username");
                    String hashedPassword = rs.getString("hashed_password");
                    String twoFactorSecret = rs.getString("two_factor_secret");
                    String encryptionSalt = rs.getString("encryption_salt");

                    return new User(userId, dbUsername, hashedPassword, twoFactorSecret, encryptionSalt);
                }
                return null;
            }
        }
    }

    /**
     * Verifica se um usuário com o dado nome de usuário existe.
     * @param username O nome de usuário a ser verificado.
     * @return true se o usuário existir, false caso contrário.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public boolean userExists(String username) throws SQLException {
         String sql = "SELECT 1 FROM users WHERE username = ?";
         try (Connection conn = getConnection();
              PreparedStatement pstmt = conn.prepareStatement(sql)) {
             pstmt.setString(1, username);
             try (ResultSet rs = pstmt.executeQuery()) {
                 return rs.next();
             }
         }
    }

    // TODO: Adicionar métodos para atualizar e deletar usuários, se necessário
} 