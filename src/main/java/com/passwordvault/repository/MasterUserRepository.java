package com.passwordvault.repository;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.passwordvault.model.MasterUser;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;

public class MasterUserRepository {
    private static final String FILE_PATH = "masteruser.json";
    private final Gson gson;

    public MasterUserRepository() {
        this.gson = new GsonBuilder().setPrettyPrinting().create();
    }

    public MasterUser loadMasterUser() {
        File file = new File(FILE_PATH);
        if (!file.exists()) {
            return null; // Usuário mestre não encontrado
        }

        try (Reader reader = new FileReader(file)) {
            return gson.fromJson(reader, MasterUser.class);
        } catch (IOException e) {
            // Em um aplicativo real, você trataria isso com mais robustez, talvez solicitando a recriação
            // ou tentando recuperar de um backup. Por enquanto, vamos lançar uma exceção de runtime.
            throw new RuntimeException("Erro ao carregar usuário mestre: " + e.getMessage());
        }
    }

    public void saveMasterUser(MasterUser user) {
        try (Writer writer = new FileWriter(FILE_PATH)) {
            gson.toJson(user, writer);
        } catch (IOException e) {
            throw new RuntimeException("Erro ao salvar usuário mestre: " + e.getMessage());
        }
    }

    public boolean exists() {
        return new File(FILE_PATH).exists();
    }
} 