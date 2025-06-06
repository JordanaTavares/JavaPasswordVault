package com.passwordvault.utils;

import java.util.Scanner;

/**
 * Classe utilitária para formatação e interação com o console.
 */
public class ConsoleUtils {

    // Códigos ANSI para cores e estilos
    public static final String RESET = "\u001B[0m";
    public static final String BLACK = "\u001B[30m";
    public static final String RED = "\u001B[31m";
    public static final String GREEN = "\u001B[32m";
    public static final String YELLOW = "\u001B[33m";
    public static final String BLUE = "\u001B[34m";
    public static final String PURPLE = "\u001B[35m";
    public static final String CYAN = "\u001B[36m";
    public static final String WHITE = "\u001B[37m";
    public static final String BOLD = "\u001B[1m";
    public static final String UNDERLINE = "\u001B[4m";

    // Caracteres para o menu
    public static final String TOP_LEFT = "╔";
    public static final String TOP_RIGHT = "╗";
    public static final String BOTTOM_LEFT = "╚";
    public static final String BOTTOM_RIGHT = "╝";
    public static final String HORIZONTAL = "═";
    public static final String VERTICAL = "║";
    public static final String T_DOWN = "╦";
    public static final String T_UP = "╩";
    public static final String T_RIGHT = "╠";
    public static final String T_LEFT = "╣";
    public static final String CROSS = "╬";

    private static final Scanner scanner = new Scanner(System.in);

    /**
     * Limpa a tela do console (pode não funcionar em todos os ambientes).
     */
    public static void clearScreen() {
        System.out.print("\033[H\033[2J");
        System.out.flush();
    }

    /**
     * Imprime um cabeçalho formatado.
     * @param title O título do cabeçalho.
     */
    public static void printHeader(String title) {
        int width = 50;
        String line = "══════════════════════════════════════════════════";
        System.out.println(line);
        int padding = (width - title.length()) / 2;
        System.out.printf("%s%s%s%s%s\n", BOLD, CYAN, " ".repeat(padding), title, RESET);
        System.out.println(line);
    }

    /**
     * Imprime uma linha divisória.
     */
    public static void printDivider() {
        System.out.println("──────────────────────────────────────────────────");
    }

    /**
     * Imprime uma opção de menu formatada.
     * @param number O número da opção.
     * @param text O texto da opção.
     */
    public static void printMenuOption(int number, String text) {
        System.out.printf(" %s%2d. %s%s%s\n", BOLD, number, CYAN, text, RESET);
    }

    /**
     * Imprime uma mensagem de informação.
     * @param message A mensagem a ser exibida.
     */
    public static void printInfo(String message) {
        System.out.println(BLUE + "ℹ " + message + RESET);
    }

    /**
     * Imprime uma mensagem de sucesso.
     * @param message A mensagem a ser exibida.
     */
    public static void printSuccess(String message) {
        System.out.println(GREEN + "✅ " + message + RESET);
    }

    /**
     * Imprime uma mensagem de aviso.
     * @param message A mensagem a ser exibida.
     */
    public static void printWarning(String message) {
        System.out.println(YELLOW + "⚠️ " + message + RESET);
    }

    /**
     * Imprime uma mensagem de erro.
     * @param message A mensagem a ser exibida.
     */
    public static void printError(String message) {
        System.out.println(RED + "❌ " + message + RESET);
    }

    /**
     * Pausa a execução e espera o usuário pressionar Enter.
     * @param prompt A mensagem a ser exibida antes de esperar o Enter.
     */
    public static void waitForEnter(String prompt) {
        printInfo(prompt);
        scanner.nextLine();
    }
} 