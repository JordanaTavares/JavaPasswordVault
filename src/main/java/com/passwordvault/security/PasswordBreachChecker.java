package com.passwordvault.security;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;

/**
 * Serviço responsável por verificar se uma senha já foi vazada usando a API haveibeenpwned.com.
 */
public class PasswordBreachChecker {
    private static final String API_URL = "https://api.pwnedpasswords.com/range/";
    private final OkHttpClient client;

    public PasswordBreachChecker() {
        this.client = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .build();
    }

    /**
     * Verifica se uma senha já foi vazada
     * @param password senha a ser verificada
     * @return número de vezes que a senha foi vazada, ou 0 se nunca foi vazada
     */
    public int checkPassword(String password) {
        try {
            String sha1Hash = getSHA1Hash(password);
            String prefix = sha1Hash.substring(0, 5);
            String suffix = sha1Hash.substring(5).toUpperCase();

            Request request = new Request.Builder()
                    .url(API_URL + prefix)
                    .addHeader("User-Agent", "PasswordVault")
                    .build();

            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    throw new RuntimeException("Erro ao verificar senha: " + response.code());
                }

                String responseBody = response.body().string();
                return findHashInResponse(responseBody, suffix);
            }
        } catch (Exception e) {
            throw new RuntimeException("Erro ao verificar senha: " + e.getMessage());
        }
    }

    private String getSHA1Hash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] hash = digest.digest(input.getBytes("UTF-8"));
        StringBuilder hexString = new StringBuilder();
        
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        
        return hexString.toString();
    }

    private int findHashInResponse(String response, String hashSuffix) {
        String[] lines = response.split("\r\n");
        for (String line : lines) {
            String[] parts = line.split(":");
            if (parts[0].equals(hashSuffix)) {
                return Integer.parseInt(parts[1]);
            }
        }
        return 0;
    }
} 