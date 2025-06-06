package com.passwordvault.utils;

import java.io.InputStream;
import java.util.Properties;

/**
 * Classe utilitária para carregar propriedades de arquivos.
 */
public class PropertyLoader {

    private static final String PROPERTIES_FILE = "application.properties";
    private static Properties properties;

    static {
        properties = new Properties();
        try (InputStream input = PropertyLoader.class.getClassLoader().getResourceAsStream(PROPERTIES_FILE)) {
            if (input == null) {
                System.err.println("Erro: Arquivo de propriedades \"" + PROPERTIES_FILE + "\" não encontrado no classpath.");
                throw new RuntimeException("Arquivo de propriedades não encontrado!");
            }
            properties.load(input);
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

    // Método de teste (opcional)
//    public static void main(String[] args) {
//        System.out.println("DB URL: " + getProperty("db.url"));
//        System.out.println("DB User: " + getProperty("db.user"));
//        System.out.println("DB Password: " + getProperty("db.password"));
//    }
} 