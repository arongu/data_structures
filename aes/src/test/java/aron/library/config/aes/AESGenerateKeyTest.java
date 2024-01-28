package aron.library.config.aes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Base64;

public class AESGenerateKeyTest {
    @Test
    @DisplayName("Generate 256 bit AES key from password as base64string")
    public void generateAESKeyFromPassword()
    throws AESToolException {
        final String password = "password";
        final String salt     = "0123456789abcdef";

        final SecretKey key       = AESEncryptDecrypt.derive256BitAESKeyWithHmacSHA256(password, salt, 500_000);
        final String    stringKey = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println(stringKey);
    }
}
