import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.sound.midi.SysexMessage;
import java.security.*;
import java.util.Base64;

/**
 * RSA is used to encrypt H(M) or symmetric key K.
 * So plaintext is String.
 */
public class RSA {
    private static final Integer KEY_LENGTH = 2048;
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(KEY_LENGTH);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String encryptHash(String hash, PrivateKey key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cipher.doFinal(hash.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String decryptHash(String hashOrKey, PublicKey key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(Base64.getDecoder().decode(hashOrKey)));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Test
    public void testRSA() {
        KeyPair keyPair = generateKeyPair();
        PublicKey puk = keyPair.getPublic();
        PrivateKey prk = keyPair.getPrivate();

        String test = "Suiren";
        String digest = MD5.calculateStringMD5(test);
        System.out.println(test + " md5: " + digest);

        String cipher = encryptHash(digest, prk);
        System.out.println(cipher);
        String plain = decryptHash(cipher, puk);
        System.out.println(plain);
    }
}
