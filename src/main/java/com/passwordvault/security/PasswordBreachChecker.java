package com.passwordvault.security;

import com.google.gson.JsonSyntaxException;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Verifica se uma senha aparece em vazamentos conhecidos usando a API Have I Been Pwned.
 */
public class PasswordBreachChecker {

    private static final String HIBP_API_URL = "https://api.pwnedpasswords.com/range/";
    private final OkHttpClient httpClient = new OkHttpClient();

    /**
     * Verifica se uma senha foi comprometida.
     * @param password A senha a ser verificada.
     * @return O número de vezes que a senha foi encontrada em vazamentos, ou -1 em caso de erro.
     */
    public int checkPassword(String password) {
        try {
            String sha1Hash = sha1(password);
            String prefix = sha1Hash.substring(0, 5);
            String suffix = sha1Hash.substring(5);

            Request request = new Request.Builder()
                    .url(HIBP_API_URL + prefix)
                    .addHeader("Add-Padding", "true") // Conformidade com a API HIBP
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    // Lidar com erros de API, talvez logar ou lançar exceção específica
                    System.err.println("Erro ao chamar a API HIBP: " + response.code());
                    return -1; // Indica erro na consulta
                }

                String responseBody = response.body().string();
                if (responseBody == null || responseBody.isEmpty()) {
                    return 0; // Não encontrada
                }

                // O corpo da resposta é uma lista de sufixos e contagens (ex: SUFFIX:COUNT)
                String[] lines = responseBody.split("\n");
                for (String line : lines) {
                    String[] parts = line.split(":");
                    if (parts.length == 2) {
                        String currentSuffix = parts[0];
                        int count = Integer.parseInt(parts[1].trim());
                        if (currentSuffix.equalsIgnoreCase(suffix)) {
                            return count; // Encontrada, retorna a contagem
                        }
                    }
                }

                return 0; // Prefixo encontrado, mas sufixo não corresponde
            }
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Erro: Algoritmo SHA-1 não disponível.");
            e.printStackTrace(); // Logar o erro interno
            return -1;
        } catch (IOException e) {
            System.err.println("Erro de I/O ao verificar a senha: " + e.getMessage());
            e.printStackTrace(); // Logar o erro de rede/I/O
            return -1;
        } catch (JsonSyntaxException e) {
            System.err.println("Erro de sintaxe JSON ao processar resposta da API HIBP.");
            e.printStackTrace(); // Logar erro de parsing JSON se o formato mudar
            return -1;
        } catch (Exception e) { // Capturar quaisquer outras exceções inesperadas
            System.err.println("Erro inesperado ao verificar senha: " + e.getMessage());
            e.printStackTrace(); // Logar erro inesperado
            return -1;
        }
    }

    /**
     * Gera o hash SHA-1 de uma string.
     * @param text O texto a ser hashed.
     * @return O hash SHA-1 em hexadecimal.
     * @throws NoSuchAlgorithmException se o algoritmo SHA-1 não estiver disponível.
     */
    private String sha1(String text) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] textBytes = text.getBytes();
        md.update(textBytes);
        byte[] digest = md.digest();
        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString().toUpperCase();
    }
} 