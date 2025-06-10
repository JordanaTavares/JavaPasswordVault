package com.passwordvault.repository;

import com.passwordvault.model.User;
import com.passwordvault.utils.PropertyLoader;
import com.passwordvault.utils.DatabaseConnectionManager;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DatabaseUserRepository {

    // Enum para indicar qual banco de dados usar
    public enum DatabaseType {
        LOCAL,
        REMOTE
    }

    // Modificar getConnection para aceitar o tipo de banco de dados
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
             // SQLite (para banco de dados local) não precisa das propriedades do MySQL 8+
             // E a URL deve ser no formato jdbc:sqlite:/caminho/para/seu/arquivo.db
             // Por enquanto, apenas verificamos a URL.

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

    /**
     * Salva um novo usuário no banco de dados.
     * @param user O objeto User a ser salvo.
     * @param type O tipo de banco de dados a ser usado.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public void saveUser(User user, DatabaseType type) throws SQLException {
        Connection conn = null;
        try {
            conn = getConnection(type);
            String sql = "INSERT INTO users (username, hashed_password, two_factor_secret, encryption_salt) VALUES (?, ?, ?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                pstmt.setString(1, user.getUsername());
                pstmt.setString(2, user.getHashedPassword());
                pstmt.setString(3, user.getTwoFactorSecret());
                pstmt.setString(4, user.getEncryptionSalt());
                pstmt.executeUpdate();

                try (ResultSet generatedKeys = pstmt.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        user.setUserId(generatedKeys.getInt(1));
                    } else {
                        // Nem todos os drivers JDBC retornam chaves geradas para AUTO_INCREMENT em todos os casos.
                        // Para o MySQL e SQLite em geral funciona, mas pode ser necessário uma query SELECT LAST_INSERT_ID() ou similar se houver problemas.
                        // Por enquanto, vamos apenas imprimir um aviso.
                        System.out.println("Aviso: Não foi possível obter o ID gerado para o usuário " + user.getUsername());
                    }
                }
            }
        } finally {
            closeConnection(conn);
        }
    }

    /**
     * Encontra um usuário pelo nome de usuário.
     * @param username O nome de usuário a ser buscado.
     * @param type O tipo de banco de dados a ser usado.
     * @return O objeto User encontrado, ou null se não existir.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public User findUserByUsername(String username, DatabaseType type) throws SQLException {
        Connection conn = null;
        try {
            conn = getConnection(type);
            String sql = "SELECT user_id, username, hashed_password, two_factor_secret, encryption_salt FROM users WHERE username = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
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
                } catch (SQLException e) {
                     // Log the exception but rethrow it
                     System.err.println("Erro ao buscar usuário por username no banco " + type + ": " + e.getMessage());
                     throw e; // Rethrow the exception
                }
            }
        } finally {
            closeConnection(conn);
        }
    }

    /**
     * Verifica se um usuário com o dado nome de usuário existe.
     * @param username O nome de usuário a ser verificado.
     * @param type O tipo de banco de dados a ser usado.
     * @return true se o usuário existir, false caso contrário.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public boolean userExists(String username, DatabaseType type) throws SQLException {
         Connection conn = null;
         try {
             conn = getConnection(type);
             String sql = "SELECT 1 FROM users WHERE username = ?";
             try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                 pstmt.setString(1, username);
                 try (ResultSet rs = pstmt.executeQuery()) {
                     return rs.next();
                 } catch (SQLException e) {
                      System.err.println("Erro ao verificar existência de usuário no banco " + type + ": " + e.getMessage());
                      throw e;
                 }
             }
         } finally {
              closeConnection(conn);
         }
    }

    /**
     * Atualiza um usuário existente no banco de dados.
     * @param user O objeto User a ser atualizado.
     * @param type O tipo de banco de dados a ser usado.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public void updateUser(User user, DatabaseType type) throws SQLException {
        Connection conn = null;
        try {
            conn = getConnection(type);
            String sql = "UPDATE users SET username = ?, hashed_password = ?, two_factor_secret = ?, encryption_salt = ? WHERE user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, user.getUsername());
                pstmt.setString(2, user.getHashedPassword());
                pstmt.setString(3, user.getTwoFactorSecret());
                pstmt.setString(4, user.getEncryptionSalt());
                pstmt.setInt(5, user.getUserId());
                pstmt.executeUpdate();
            }
        } finally {
            closeConnection(conn);
        }
    }

    /**
     * Remove um usuário do banco de dados.
     * @param userId O ID do usuário a ser removido.
     * @param type O tipo de banco de dados a ser usado.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public void deleteUser(int userId, DatabaseType type) throws SQLException {
        Connection conn = null;
        try {
            conn = getConnection(type);
            String sql = "DELETE FROM users WHERE user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setInt(1, userId);
                pstmt.executeUpdate();
            }
        } finally {
            closeConnection(conn);
        }
    }

    /**
     * Busca o nome de usuário pelo seu ID em um banco de dados específico.
     * @param userId O ID do usuário a ser buscado.
     * @param type O tipo de banco de dados a ser usado (LOCAL ou REMOTE).
     * @return O nome de usuário encontrado, ou null se não existir.
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public String findUsernameByUserId(int userId, DatabaseType type) throws SQLException {
        Connection conn = null;
        try {
            conn = getConnection(type);
            String sql = "SELECT username FROM users WHERE user_id = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setInt(1, userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString("username");
                    }
                    return null;
                } catch (SQLException e) {
                     System.err.println("Erro ao buscar username por user_id no banco " + type + ": " + e.getMessage());
                     throw e;
                }
            }
        } finally {
            closeConnection(conn);
        }
    }

    /**
     * Sincroniza usuários do banco de dados remoto para o banco de dados local.
     * Adiciona usuários remotos ao local se não existirem (baseado no username).
     * @throws SQLException se ocorrer um erro de banco de dados.
     */
    public Map<String, Integer> syncUsers() throws SQLException {
        Connection conn = null;
        Map<String, Integer> localUserIds = new HashMap<>();
        try {
            conn = getConnection(DatabaseType.REMOTE);
            // Buscar todos os usuários do banco remoto
            List<User> remoteUsers = new ArrayList<>();
            String selectRemoteSql = "SELECT user_id, username, hashed_password, two_factor_secret, encryption_salt FROM users";
            try (PreparedStatement pstmt = conn.prepareStatement(selectRemoteSql);
                 ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    int userId = rs.getInt("user_id");
                    String dbUsername = rs.getString("username");
                    String hashedPassword = rs.getString("hashed_password");
                    String twoFactorSecret = rs.getString("two_factor_secret");
                    String encryptionSalt = rs.getString("encryption_salt");
                    remoteUsers.add(new User(userId, dbUsername, hashedPassword, twoFactorSecret, encryptionSalt));
                }
            }

            // Para cada usuário remoto, verifique se ele existe localmente e adicione se não
            for (User remoteUser : remoteUsers) {
                // Usamos o username para verificar a existência local, pois user_id será diferente
                User localUser = findUserByUsername(remoteUser.getUsername(), DatabaseType.LOCAL);
                if (localUser == null) {
                    // Usuário remoto não existe localmente, salve-o (o ID local será gerado)
                    System.out.println("Sincronizando usuário para o banco local: " + remoteUser.getUsername());
                    // Ao salvar, o saveUser atualiza o objeto remoteUser com o ID local gerado
                    saveUser(remoteUser, DatabaseType.LOCAL);
                    // Usar o ID local obtido após salvar
                    localUserIds.put(remoteUser.getUsername(), remoteUser.getUserId());
                } else {
                     System.out.println("Usuário já existe localmente: " + remoteUser.getUsername() + ". Ignorando atualização.");
                     // Usar o ID local do usuário existente
                     localUserIds.put(localUser.getUsername(), localUser.getUserId());
                }
            }
            return localUserIds;
        } finally {
            closeConnection(conn);
        }
    }

    /**
     * Sincroniza apenas um usuário específico entre o banco remoto e local.
     * @param user O usuário a ser sincronizado
     * @return Um mapa contendo o username e o ID local do usuário
     * @throws SQLException se ocorrer um erro de banco de dados
     */
    public Map<String, Integer> syncSingleUser(User user) throws SQLException {
        Map<String, Integer> localUserIds = new HashMap<>();
        
        // Verificar se o usuário já existe localmente
        User localUser = findUserByUsername(user.getUsername(), DatabaseType.LOCAL);
        
        if (localUser == null) {
            // Usuário não existe localmente, salvar
            saveUser(user, DatabaseType.LOCAL);
            localUserIds.put(user.getUsername(), user.getUserId());
        } else {
            // Usuário já existe, usar o ID local existente
            localUserIds.put(localUser.getUsername(), localUser.getUserId());
        }
        
        return localUserIds;
    }

    // Adicionar método para fechar conexão
    private void closeConnection(Connection conn) {
        if (conn != null) {
            DatabaseConnectionManager.getInstance().closeConnection(conn);
        }
    }
} 