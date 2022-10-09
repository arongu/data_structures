package encryptor;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ConfigFieldTester {
    @Test
    public void loadAESKeyFromFile_shouldReadFirstLineFromFileAndReturnItAsBytes_whenExecuted() throws IOException {
        final String originalKeyAsHex = "a3224844f478d92cf2c81cf262fddfa379c74fff91a17651df24c601cab6be4b";
        final URL keyFileUrl = getClass().getClassLoader().getResource("key.txt");

        final byte[] bytes = ConfigEncryptor.loadAESKeyFromFile(keyFileUrl.getPath()).getEncoded();
        final String loadedKeyAsHex = Hex.encodeHexString(bytes);

        assertEquals(originalKeyAsHex, loadedKeyAsHex);
    }
}
