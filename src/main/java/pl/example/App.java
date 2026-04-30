package pl.example;

import org.apache.commons.lang3.StringUtils;

public class App {
    public static void main(String[] args) {
        String text = "test builda gitlab";
        // Używamy metody z biblioteki commons-lang3
        System.out.println(StringUtils.capitalize(text) + " - DZIAŁA!");
    }
}
