/**
 * Vulnerable Java Application - FOR TESTING PURPOSES ONLY
 * This file contains intentional security vulnerabilities for demonstration.
 * DO NOT USE IN PRODUCTION!
 */

import java.sql.*;
import java.io.*;
import java.util.*;
import javax.servlet.http.*;
import java.security.MessageDigest;

public class VulnerableJavaApp {
    
    // Vulnerability: Hardcoded credentials
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdef";
    
    // Vulnerability: SQL Injection
    public User authenticateUser(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/mydb", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        
        // VULNERABLE: SQL Injection - direct string concatenation
        String query = "SELECT * FROM users WHERE username = '" + username + 
                      "' AND password = '" + password + "'";
        ResultSet rs = stmt.executeQuery(query);
        
        if (rs.next()) {
            return new User(rs.getString("username"), rs.getString("email"));
        }
        return null;
    }
    
    // Vulnerability: Command Injection
    public String executeCommand(String userInput) {
        try {
            // VULNERABLE: Command injection
            Process process = Runtime.getRuntime().exec("ping -c 1 " + userInput);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Vulnerability: Path Traversal
    public String readFile(String filename) {
        try {
            // VULNERABLE: No input validation for file paths
            File file = new File(filename);
            Scanner scanner = new Scanner(file);
            StringBuilder content = new StringBuilder();
            while (scanner.hasNextLine()) {
                content.append(scanner.nextLine()).append("\n");
            }
            scanner.close();
            return content.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Vulnerability: Weak Cryptography
    public String hashPassword(String password) {
        try {
            // VULNERABLE: Using MD5 for password hashing
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }
    
    // Vulnerability: Insecure Deserialization
    public Object deserializeObject(String serializedData) {
        try {
            // VULNERABLE: Deserializing untrusted data
            byte[] data = Base64.getDecoder().decode(serializedData);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            return ois.readObject();
        } catch (Exception e) {
            return null;
        }
    }
    
    // Vulnerability: XXE (XML External Entity)
    public String parseXML(String xmlData) {
        try {
            // VULNERABLE: XML parser allows external entities
            javax.xml.parsers.DocumentBuilderFactory factory = 
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(new java.io.StringBufferInputStream(xmlData));
            return doc.getDocumentElement().getNodeName();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Vulnerability: Insecure Random Number Generation
    public String generateToken() {
        // VULNERABLE: Using predictable random number generator
        Random random = new Random(System.currentTimeMillis());
        return String.valueOf(random.nextLong());
    }
    
    // Vulnerability: Information Disclosure
    public String getSystemInfo() {
        StringBuilder info = new StringBuilder();
        // VULNERABLE: Exposing sensitive system information
        info.append("Java Version: ").append(System.getProperty("java.version")).append("\n");
        info.append("OS: ").append(System.getProperty("os.name")).append("\n");
        info.append("User: ").append(System.getProperty("user.name")).append("\n");
        info.append("Home: ").append(System.getProperty("user.home")).append("\n");
        info.append("API Key: ").append(API_KEY).append("\n");
        return info.toString();
    }
    
    // Vulnerability: LDAP Injection
    public boolean authenticateLDAP(String username, String password) {
        try {
            // VULNERABLE: LDAP injection
            String filter = "(&(uid=" + username + ")(password=" + password + "))";
            // ... LDAP authentication code would go here
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    // Vulnerability: Reflection abuse
    public Object createInstance(String className) {
        try {
            // VULNERABLE: Unrestricted class instantiation
            Class<?> clazz = Class.forName(className);
            return clazz.newInstance();
        } catch (Exception e) {
            return null;
        }
    }
    
    // Helper class
    public static class User {
        private String username;
        private String email;
        
        public User(String username, String email) {
            this.username = username;
            this.email = email;
        }
        
        // Getters
        public String getUsername() { return username; }
        public String getEmail() { return email; }
    }
    
    public static void main(String[] args) {
        System.out.println("Vulnerable Java Application - FOR TESTING ONLY");
        System.out.println("This application contains intentional security vulnerabilities!");
    }
}