package com.passwordvault.utils;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Gerenciador de conexões com o banco de dados.
 * Esta classe mantém o controle de todas as conexões ativas e garante que sejam fechadas corretamente.
 */
public class DatabaseConnectionManager {
    private static final DatabaseConnectionManager instance = new DatabaseConnectionManager();
    private final List<Connection> activeConnections;
    private static final Thread shutdownHook;

    static {
        shutdownHook = new Thread(() -> {
            System.out.println("Fechando todas as conexões com o banco de dados...");
            getInstance().closeAllConnections();
        });
        Runtime.getRuntime().addShutdownHook(shutdownHook);
    }

    private DatabaseConnectionManager() {
        this.activeConnections = new CopyOnWriteArrayList<>();
    }

    public static DatabaseConnectionManager getInstance() {
        return instance;
    }

    /**
     * Obtém uma conexão com o banco de dados e a registra para controle.
     */
    public Connection getConnection(String url, String user, String password) throws SQLException {
        Connection conn = DriverManager.getConnection(url, user, password);
        activeConnections.add(conn);
        return conn;
    }

    /**
     * Remove uma conexão da lista de conexões ativas.
     */
    public void removeConnection(Connection conn) {
        activeConnections.remove(conn);
    }

    /**
     * Fecha todas as conexões ativas.
     */
    public void closeAllConnections() {
        List<Connection> connectionsToClose = new ArrayList<>(activeConnections);
        for (Connection conn : connectionsToClose) {
            try {
                if (conn != null && !conn.isClosed()) {
                    conn.close();
                    removeConnection(conn);
                }
            } catch (SQLException e) {
                System.err.println("Erro ao fechar conexão: " + e.getMessage());
            }
        }
    }

    /**
     * Fecha uma conexão específica e a remove da lista de conexões ativas.
     */
    public void closeConnection(Connection conn) {
        if (conn != null) {
            try {
                if (!conn.isClosed()) {
                    conn.close();
                }
                removeConnection(conn);
            } catch (SQLException e) {
                System.err.println("Erro ao fechar conexão: " + e.getMessage());
            }
        }
    }
} 