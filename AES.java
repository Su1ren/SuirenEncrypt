import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class AES {
    private static final String SUFFIX = ".aes";
    private static final int KEY_LENGTH = 128;
    private static final int BYTES = KEY_LENGTH / 8;

    public static String encryptWithKey(String plaintext, String key) throws Exception {
        System.out.println("Encrypting with AES...");
        System.out.println("Key: " + key);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public static String encryptWithGenKey(String plaintext) throws Exception {
        return encryptWithKey(plaintext, generateKey());
    }

    public static String decryptWithKey(String ciphertext, String key) throws Exception {
        System.out.println("Decrypting AES...");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted);
    }

    public static String generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(KEY_LENGTH, new SecureRandom()); // 128 位密钥
        SecretKey key = keyGen.generateKey();
        return keyLengthProcess(secretKeyToString(key));
    }

    private static String secretKeyToString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static void encryptFile(String key, String inputFile, String outputFile) throws Exception {
        System.out.println("Encrypting file..." + inputFile);
        System.out.println("Key: " + key);

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }
    }

    public static void decryptFile(String key, String inputFile, String outputFile) throws Exception {
        System.out.println("Decrypting file..." + inputFile);

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile);
             CipherInputStream cis = new CipherInputStream(fis, cipher)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
        }
    }

    private static String keyLengthProcess(String key) {
        if (key.length() < BYTES) {
            return key + "0".repeat(BYTES - key.length());
        }
        return key.substring(0, BYTES);
    }

    @Test
    public void testString() throws Exception {
        String plaintext = "Hello, world!"; // 要加密的字符串
        String secretKey = keyLengthProcess("12345678"); // 加密密钥
        System.out.println(encryptWithKey(plaintext, secretKey));

        String decrypted = decryptWithKey(encryptWithKey(plaintext, secretKey), secretKey);
        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testGenerateKey() {
        try {
            String plaintext = "Hello, world!"; // 要加密的字符串
            String ciphertext = encryptWithGenKey(plaintext);
            Scanner scanner = new Scanner(System.in);
            String key = scanner.nextLine();
            String decrypted = decryptWithKey(ciphertext, key);
            assertEquals(plaintext, decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testFile() throws Exception {
        String secretKey = keyLengthProcess("SuirenEncrypt");
        try {
            encryptFile(secretKey, "README.md", "README.aes");
            decryptFile(secretKey, "README.aes", "README1.md");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}