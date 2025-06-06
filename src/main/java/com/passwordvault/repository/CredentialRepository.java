package com.passwordvault.repository;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.passwordvault.model.Credential;
import com.passwordvault.security.EncryptionService;
import com.passwordvault.utils.LocalDateTimeAdapter;

import java.io.*;
import java.lang.reflect.Type;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Repositório responsável pela persistência das credenciais em arquivo JSON.
 */
public class CredentialRepository {
    private static final String FILE_PATH = "credentials.json";
    private final Gson gson;
    private final EncryptionService encryptionService;
    private List<Credential> credentials;

    public CredentialRepository(EncryptionService encryptionService) {
        this.encryptionService = encryptionService;
        this.gson = new GsonBuilder()
            .setPrettyPrinting()
            .registerTypeAdapter(LocalDateTime.class, new LocalDateTimeAdapter())
            .create();
        this.credentials = loadCredentials();
    }

    /**
     * Carrega as credenciais do arquivo JSON
     * @return lista de credenciais
     */
    private List<Credential> loadCredentials() {
        File file = new File(FILE_PATH);
        if (!file.exists()) {
            return new ArrayList<>();
        }

        try (Reader reader = new FileReader(file)) {
            Type type = new TypeToken<List<Credential>>(){}.getType();
            List<Credential> loadedCredentials = gson.fromJson(reader, type);
            return loadedCredentials;
        } catch (IOException e) {
            throw new RuntimeException("Erro ao carregar credenciais: " + e.getMessage());
        }
    }

    /**
     * Salva as credenciais no arquivo JSON
     */
    private void saveCredentials() {
        try (Writer writer = new FileWriter(FILE_PATH)) {
            gson.toJson(credentials, writer);
        } catch (IOException e) {
            throw new RuntimeException("Erro ao salvar credenciais: " + e.getMessage());
        }
    }

    /**
     * Adiciona uma nova credencial
     * @param credential credencial a ser adicionada
     */
    public void addCredential(Credential credential) {
        credentials.add(credential);
        saveCredentials();
    }

    /**
     * Atualiza uma credencial existente
     * @param credential credencial atualizada
     */
    public void updateCredential(Credential credential) {
        Optional<Credential> existingCredential = credentials.stream()
                .filter(c -> c.getId().equals(credential.getId()))
                .findFirst();

        if (existingCredential.isPresent()) {
            int index = credentials.indexOf(existingCredential.get());
            credentials.set(index, credential);
            saveCredentials();
        }
    }

    /**
     * Remove uma credencial
     * @param id ID da credencial a ser removida
     */
    public void removeCredential(String id) {
        credentials.removeIf(c -> c.getId().equals(id));
        saveCredentials();
    }

    /**
     * Busca uma credencial pelo ID
     * @param id ID da credencial
     * @return credencial encontrada ou null
     */
    public Optional<Credential> findById(String id) {
        return credentials.stream()
                .filter(c -> c.getId().equals(id))
                .findFirst();
    }

    /**
     * Lista todas as credenciais
     * @return lista de credenciais
     */
    public List<Credential> findAll() {
        return new ArrayList<>(credentials);
    }

    /**
     * Busca credenciais por serviço
     * @param service nome do serviço
     * @return lista de credenciais do serviço
     */
    public List<Credential> findByService(String service) {
        return credentials.stream()
                .filter(c -> c.getService().equalsIgnoreCase(service))
                .toList();
    }
} 