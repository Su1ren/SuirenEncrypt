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
     * @param seed the seed to generate key for the encryption
     * @return the encrypted string
     * @throws Exception if there is an error encrypting
     */
    private static String encryptWithSeed(String plaintext, String seed) throws Exception {
        System.out.println("Encrypting with DES...");
        System.out.println("Seed: " + seed);

        SecretKey secretKey = new SecretKeySpec(seed.getBytes(), "DES");
        return encryptWithKey(plaintext, secretKey);
    }

    public static String encryptWithKey(String plaintext, SecretKey key) {
        try {
            System.out.println("Key: " + secretKeyToBase64(key));
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(ciphertext);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
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

        SecretKey key = generateRandomKey();
        System.out.println("Key: " + secretKeyToBase64(key));

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        return Base64.getEncoder().encodeToString(ciphertext);
    }

    /**
     * Decrypts a given string using DES encryption and a given key.
     *
     * @param ciphertext the ciphertext string to be decrypted
     * @param key the key to use for the decryption
     * @return the decrypted string
     * @throws Exception if there is an error decrypting
     */
    private static String decryptWithKey(String ciphertext, SecretKey key) throws Exception {
        System.out.println("Decrypting with DES...");

        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted);
    }

    /**
     * Encrypts a given file using DES encryption and a given key.
     *
     * @param inputFile  the file to be encrypted
     * @param outputFile the file to write the encrypted data to
     * @param key  the key to use for the encryption
     * @throws Exception if there is an error encrypting
     */
    public static void encryptFile(String inputFile, String outputFile, SecretKey key) throws Exception {

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
     * @param key  the key to use for the decryption
     * @throws Exception if there is an error decrypting
     */
    public static void decryptFile(String inputFile, String outputFile, SecretKey key) throws Exception {

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
        String seed = "12345678"; // 种子
        SecretKey key = new SecretKeySpec(seed.getBytes(), "DES");
        System.out.println(encryptWithSeed(plaintext, seed));
        String decrypted = decryptWithKey(encryptWithSeed(plaintext, seed), key);
        assert decrypted.equals(plaintext);
    }

    /**
     * Generates a random DES key.
     *
     * @return a random DES key with 8 bytes (56 bits) of randomness, padded with 0s
     *         to be 8 bytes long.
     * @throws RuntimeException if an error occurs while generating the key
     */
    private static SecretKey generateRandomKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(KEY_LENGTH);
            SecretKey key = keyGen.generateKey();
            return key;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static SecretKey base64ToSecretKey(String base64Key) {
        return new SecretKeySpec(Base64.getDecoder().decode(base64Key), "DES");
    }

    @Test
    public void testRandomKey() throws Exception {
        String plaintext = "Hello, world!"; // 要加密的字符串
        SecretKey key = generateRandomKey();
        String ciphertext = encryptWithKey(plaintext, key);
        System.out.println(decryptWithKey(ciphertext, key));
    }

    @Test
    public void testGenKey() throws Exception {
        String plaintext = "Hello, world!"; // 要加密的字符串
        String ciphertext = encryptWithGenKey(plaintext);
        Scanner scanner = new Scanner(System.in);
        String key = scanner.nextLine();
        System.out.println(decryptWithKey(ciphertext, base64ToSecretKey(key)));
    }

    @Test
    public void testRandom() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        SecretKey key = keyGen.generateKey();
        String plaintext = "Hello, world!"; // 要加密的字符串
        System.out.println(plaintext);
        System.out.println(secretKeyToBase64(key));
        String encrypted = encrypt(plaintext, key);
        System.out.println(encrypted);
        String decrypted = decrypt(encrypted, key);
        System.out.println(decrypted);
    }

    private static String secretKeyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // 解密方法
    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedData);
    }
}
