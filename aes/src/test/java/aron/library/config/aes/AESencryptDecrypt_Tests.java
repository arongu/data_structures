package aron.library.config.aes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AESencryptDecrypt_Tests {
    @Test
    @DisplayName("encrypt -> decrypt with generated AES 256 bit key")
    public void testEncryptDecryptWithKey()
    throws AESToolException {
        final SecretKey secretKey  = KeyGenerator.generate256bitAESkey();
        final String    message    = "This is my super secret message.";
        final String    cipherText = AESEncryptDecrypt.encryptStringWithKeyToBase64CipherText(secretKey, message);
        final String    decrypted  = AESEncryptDecrypt.decryptBase64CipherTextWithKeyToString(secretKey, cipherText);

        assertEquals(message, decrypted);
    }
}

