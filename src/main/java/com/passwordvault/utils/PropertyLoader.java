package com.passwordvault.utils;

import java.io.InputStream;
import java.util.Properties;

/**
 * Classe utilitária para carregar propriedades de arquivos.
 */
public class PropertyLoader {

    private static final String PROPERTIES_FILE = "application.properties";
    private static Properties properties;

    // Propriedades para o banco de dados remoto (usado para sincronização e como primário atualmente)
    private static String dbRemoteUrl;
    private static String dbRemoteUser;
    private static String dbRemotePassword;

    // Novas propriedades para o banco de dados local (usado para modo offline)
    private static String dbLocalUrl;
    private static String dbLocalUser;
    private static String dbLocalPassword;

    static {
        properties = new Properties();
        try (InputStream input = PropertyLoader.class.getClassLoader().getResourceAsStream(PROPERTIES_FILE)) {
            if (input == null) {
                System.err.println("Erro: Arquivo de propriedades \"" + PROPERTIES_FILE + "\" não encontrado no classpath.");
                throw new RuntimeException("Arquivo de propriedades não encontrado!");
            }
            properties.load(input);

            // Carregar propriedades do banco de dados remoto
            dbRemoteUrl = properties.getProperty("db.url");
            dbRemoteUser = properties.getProperty("db.user");
            dbRemotePassword = properties.getProperty("db.password");

            // Carregar propriedades do banco de dados local
            dbLocalUrl = properties.getProperty("db.local.url");
            dbLocalUser = properties.getProperty("db.local.user");
            dbLocalPassword = properties.getProperty("db.local.password");

        } catch (Exception e) {
            System.err.println("Erro ao carregar o arquivo de propriedades: " + PROPERTIES_FILE);
            e.printStackTrace();
            throw new RuntimeException("Erro ao carregar arquivo de propriedades!", e);
        }
    }

    /**
     * Obtém o valor de uma propriedade.
     * @param key A chave da propriedade.
     * @return O valor da propriedade, ou null se não encontrada.
     */
    public static String getProperty(String key) {
        return properties.getProperty(key);
    }

    /**
     * Obtém o valor de uma propriedade, com um valor padrão.
     * @param key A chave da propriedade.
     * @param defaultValue O valor padrão a ser retornado se a propriedade não for encontrada.
     * @return O valor da propriedade, ou o valor padrão se não encontrada.
     */
    public static String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    // Novos métodos para obter propriedades específicas do banco de dados remoto e local

    public static String getDbRemoteUrl() {
        return dbRemoteUrl;
    }

    public static String getDbRemoteUser() {
        return dbRemoteUser;
    }

    public static String getDbRemotePassword() {
        return dbRemotePassword;
    }

    public static String getDbLocalUrl() {
        return dbLocalUrl;
    }

    public static String getDbLocalUser() {
        return dbLocalUser;
    }

    public static String getDbLocalPassword() {
        return dbLocalPassword;
    }

    // Método de teste (opcional)
//    public static void main(String[] args) {
//        System.out.println("DB Remote URL: " + getDbRemoteUrl());
//        System.out.println("DB Remote User: " + getDbRemoteUser());
//        System.out.println("DB Remote Password: " + getDbRemotePassword());
//        System.out.println("DB Local URL: " + getDbLocalUrl());
//        System.out.println("DB Local User: " + getDbLocalUser());
//        System.out.println("DB Local Password: " + getDbLocalPassword());
//    }
} 