import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

public class PasswordManager {
    private static SecretKey secretKey;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Generate secret key
        try {
            secretKey = generateSecretKey();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating secret key: " + e.getMessage());
            return;
        }

        // Get password from user
        System.out.println("Enter your password: ");
        String password = scanner.nextLine();

        // Validate password strength
        if (!isValidPassword(password)) {
            System.out.println("Password is not strong enough.");
            return;
        }

        // Encrypt and save password
        String encryptedPassword = encryptPassword(password);
        System.out.println("Encrypted password: " + encryptedPassword);

        scanner.close();
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // Using AES with 128-bit key size
        return keyGenerator.generateKey();
    }

    private static boolean isValidPassword(String password) {
        // Implement your password strength validation logic here
        // For example, check length, presence of uppercase, lowercase, digits, special characters, etc.
        return password.length() >= 8 && password.matches(".*[A-Z].*") && password.matches(".*[a-z].*") && password.matches(".*\\d.*");
    }

    private static String encryptPassword(String password) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(password.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            System.err.println("Error encrypting password: " + e.getMessage());
            return null;
        }
    }
}
