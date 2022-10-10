package aron.encryptor;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ConfigEncryptorTest {
    @Test
    public void loadAESKeyFromFile_shouldReadFirstLineFromFileAndReturnItAsBytes_whenExecuted() throws IOException {
        final String originalKeyAsHex = "90de81ff28dfc13e6f660281a083c48279cb889f9a85e9b6f9353ed673b960f4";
        final URL keyFileUrl = getClass().getClassLoader().getResource("key.conf");

        final byte[] bytes = ConfigEncryptor.loadAESKeyFromFile(keyFileUrl.getPath()).getEncoded();
        final String loadedKeyAsHex = Hex.encodeHexString(bytes);

        assertEquals(originalKeyAsHex, loadedKeyAsHex);
    }
}
