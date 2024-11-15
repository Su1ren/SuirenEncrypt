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

public class AES {
    private static final String SUFFIX = ".aes";
//    public static void main(String[] args) {
//        try {
//            String originalFile = "path/to/original/file.txt"; // 源文件路径
//            String encryptedFile = "path/to/encrypted/file.aes"; // 加密后文件路径
//            String decryptedFile = "path/to/decrypted/file.txt"; // 解密后文件路径
//
//            // 生成 AES 密钥
//            SecretKey secretKey = generateKey();
//
//            // 加密文件
//            encryptFile(secretKey, originalFile, encryptedFile);
//            System.out.println("File encrypted successfully.");
//
//            // 解密文件
//            decryptFile(secretKey, encryptedFile, decryptedFile);
//            System.out.println("File decrypted successfully.");
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }

    public static String encryptWithKey(String plaintext, SecretKey key) throws Exception {
        System.out.println("Encrypting with AES...");
        System.out.println("Key: " + Base64.getEncoder().encodeToString(key.getEncoded()));

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public static String encryptWithGenKey(String plaintext) throws Exception {
        return encryptWithKey(plaintext, generateKey());
    }

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom()); // 256 位密钥
        return keyGen.generateKey();
    }

    public static void encryptFile(SecretKey key, String inputFile, String outputFile) throws Exception {
        System.out.println("Encrypting file..." + inputFile);
        System.out.println("Key: " + Base64.getEncoder().encodeToString(key.getEncoded()));

        Cipher cipher = Cipher.getInstance("AES");
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

    public static void decryptFile(SecretKey key, String inputFile, String outputFile) throws Exception {
        System.out.println("Decrypting file..." + inputFile);

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

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
}