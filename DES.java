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
import java.util.Scanner;

/**
 * In the project, DES is used to encrypt M || RSA(H(M), RKa)
 */
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
        System.out.println("Encrypting DES with random key.");

        String key = generateRandomKey();
        System.out.println("Key: " + key);

        return encryptWithKey(plaintext, key);
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
        System.out.println("Decrypting with DES...");

        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "DES"));
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted);
    }

    /**
     * Encrypts a given file using DES encryption and a given key.
     *
     * @param inputFile  the file to be encrypted
     * @param outputFile the file to write the encrypted data to
     * @param secretKey  the key to use for the encryption
     * @throws Exception if there is an error encrypting
     */
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

    /**
     * Decrypts a given file using DES encryption and a given key.
     *
     * @param inputFile  the file to be decrypted
     * @param outputFile the file to write the decrypted data to
     * @param secretKey  the key to use for the decryption
     * @throws Exception if there is an error decrypting
     */
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

    /**
     * Generates a random DES key.
     *
     * @return a random DES key with 8 bytes (56 bits) of randomness, padded with 0s
     *         to be 8 bytes long.
     * @throws RuntimeException if an error occurs while generating the key
     */
    private static String generateRandomKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(KEY_LENGTH);
            SecretKey key = keyGen.generateKey();
            return keyLengthProcess(secretKeyToString(key));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Converts a {@link SecretKey} object to a string representation of its
     * raw bytes, encoded in Base64.
     *
     * @param secretKey the key to be converted
     * @return a string representation of the key's raw bytes, encoded in Base64
     */
    private static String secretKeyToString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        // return new String(secretKey.getEncoded());
    }

    /**
     * Process the length of the key. If the length of the key is less than 8, pad
     * it with 0s to be 8 bytes long. If the length of the key is more than 8,
     * truncate it to be 8 bytes long.
     *
     * @param key the key to be processed
     * @return the processed key
     */
    private static String keyLengthProcess(String key) {
        if (key.length() < 8) {
            for (int i = 0; i < 8 - key.length(); i++) {
                key += "0";
            }
        } else if (key.length() > 8) {
            key = key.substring(0, 8);
        }
        return key;
    }


    @Test
    public void testRandomKey() throws Exception {
        String plaintext = "Hello, world!"; // 要加密的字符串
        String key = generateRandomKey();
        String ciphertext = encryptWithKey(plaintext, key);
        System.out.println(decryptWithKey(ciphertext, key));
    }

    @Test
    public void testGenKey() throws Exception {
        String plaintext = "Hello, world!"; // 要加密的字符串
        String ciphertext = encryptWithGenKey(plaintext);
        Scanner scanner = new Scanner(System.in);
        String key = scanner.nextLine();
        System.out.println(decryptWithKey(ciphertext, key));
    }
}
