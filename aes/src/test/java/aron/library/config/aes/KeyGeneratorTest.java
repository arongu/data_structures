package aron.library.config.aes;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class KeyGeneratorTest {
    @Test
    public void generateKeyAsBase64_shouldNotThrowException_whenCalled() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final String password = "password";
        final String salt = "salt";

        final String base64key = KeyGenerator.generateKeyAsBase64(password, salt, 250000, 256);
        System.out.println(base64key);
        assertNotNull(base64key);
    }

    @Test
    public void generate256bitAESkey_shouldNotThrowException_whenCalled() {
        final SecretKey key = KeyGenerator.generate256bitAESkey();
    }
}
