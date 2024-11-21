import org.junit.Test;

import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class DES {
    private static final String SUFFIX = ".des";
    private static final int KEY_LENGTH = 56;
    /**
     * Encrypts a given string and provide a key using DES encryption.
     *
     * @param plaintext the plaintext string to be encrypted
     * @param key the key to use for the encryption
     * @return the encrypted string
     * @throws Exception if there is an error encrypting
     */
    private static String encryptWithKey(String plaintext, String key) throws Exception {
        System.out.println("Encrypting with DES...");
        System.out.println("Key: " + key);

        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        return Base64.getEncoder().encodeToString(ciphertext);
    }

    /**
     * Encrypts a given string using DES encryption and a randomly generated key.
     *
     * @param plaintext the plaintext string to be encrypted
     * @return the encrypted string
     * @throws Exception if there is an error encrypting
     */
    private static String encryptWithGenKey(String plaintext) throws Exception {
        System.out.println("Encrypting with DES...");

        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(KEY_LENGTH);
        SecretKey secretKey = keyGenerator.generateKey();

        return encryptWithKey(plaintext, Base64.getEncoder().encodeToString(secretKey.getEncoded()));
    }

    /**
     * Decrypts a given string using DES encryption and a given key.
     *
     * @param ciphertext the ciphertext string to be decrypted
     * @param key the key to use for the decryption
     * @return the decrypted string
     * @throws Exception if there is an error decrypting
     */
    private static String decryptWithKey(String ciphertext, String key) throws Exception {
        System.out.println("Decrypting DES...");

        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "DES"));
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted);
    }

    public static void encryptFile(String inputFile, String outputFile, String secretKey) throws Exception {
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "DES");

        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

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

    public static void decryptFile(String inputFile, String outputFile, String secretKey) throws Exception {
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "DES");

        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);

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

    public static void main(String[] args) throws Exception {
        String plaintext = "Hello, world!"; // 要加密的字符串
        String secretKey = "12345678"; // 加密密钥
        System.out.println(encryptWithKey(plaintext, secretKey));
        String decrypted = decryptWithKey(encryptWithKey(plaintext, secretKey), secretKey);
        assert decrypted.equals(plaintext);
    }

}
