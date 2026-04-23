package com.example.test;

import java.util.ArrayList;
import java.util.List;

public class TestPlugin {
    private static final String SECRET_KEY = "mySecretKey123";
    private int counter = 0;
    
    public static void main(String[] args) {
        TestPlugin plugin = new TestPlugin();
        plugin.onEnable();
        
        String message = plugin.decryptMessage("Hello World");
        System.out.println(message);
        
        int result = plugin.calculate(42, 8);
        System.out.println("Result: " + result);
    }
    
    public void onEnable() {
        System.out.println("Plugin enabled!");
        List<String> items = new ArrayList<>();
        items.add("item1");
        items.add("item2");
        
        for (String item : items) {
            System.out.println("Item: " + item);
        }
    }
    
    public String decryptMessage(String msg) {
        return "Decrypted: " + msg + " with key: " + SECRET_KEY;
    }
    
    public int calculate(int a, int b) {
        counter++;
        return (a * b) + counter;
    }
}
