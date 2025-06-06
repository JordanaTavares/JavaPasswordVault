package com.passwordvault.utils;

public class ConsoleUtils {
    // Cores ANSI
    public static final String RESET = "\u001B[0m";
    public static final String BLACK = "\u001B[30m";
    public static final String RED = "\u001B[31m";
    public static final String GREEN = "\u001B[32m";
    public static final String YELLOW = "\u001B[33m";
    public static final String BLUE = "\u001B[34m";
    public static final String PURPLE = "\u001B[35m";
    public static final String CYAN = "\u001B[36m";
    public static final String WHITE = "\u001B[37m";

    // Estilos
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

    public static void clearScreen() {
        System.out.print("\033[H\033[2J");
        System.out.flush();
    }

    public static void printHeader(String title) {
        ConsoleUtils.printDivider();
        System.out.println(BOLD + CYAN + title + RESET);
        ConsoleUtils.printDivider();
    }

    public static void printMenuOption(int number, String text) {
        System.out.println(BOLD + YELLOW + "  " + number + ". " + RESET + text);
    }

    public static void printSuccess(String message) {
        System.out.println(BOLD + GREEN + "✓ " + message + RESET);
    }

    public static void printError(String message) {
        System.out.println(BOLD + RED + "✗ " + message + RESET);
    }

    public static void printWarning(String message) {
        System.out.println(BOLD + YELLOW + "⚠ " + message + RESET);
    }

    public static void printInfo(String message) {
        System.out.println(BOLD + BLUE + "ℹ " + message + RESET);
    }

    public static void printDivider() {
        System.out.println(BOLD + BLUE + HORIZONTAL.repeat(50) + RESET);
    }
} 