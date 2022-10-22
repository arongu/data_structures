package aron.lib.config.lib.config.loader;

import aron.lib.config.lib.config.encryptor.ConfigEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Properties;

/**
 * Opens and loads the encrypted configuration file and makes the properties available to different classes.
 */
public class ConfigLoader {
    private static final Logger logger = LoggerFactory.getLogger(ConfigLoader.class);
    private String keyFile, confFile;
    private Properties properties;

    /**
     * Loads the configuration when the application is started.
     * @param keyFile Path of the decryption key file.
     * @param confFile Path of the encrypted configuration file.
     */
    public ConfigLoader(final String keyFile, final String confFile) throws IOException {
        this.keyFile = keyFile;
        this.confFile = confFile;
        loadAndDecryptConfigFile();
    }

    /**
     * Opens both the keyFile and confFile and decrypts it, then loads the decrypted data into separate Properties.
     * db_user_properties -- properties of "user" db, which only handles user related data
     * db_work_properties -- properties of "work" db, which only handles application related data
     * app_properties     -- properties of cornerstone itself (e.g.: rotation interval, node name etc.)
     * @throws IOException When the underlying ConfigEncryptDecrypt files to load the keyfile or fails to decrypt the config file.
     */
    public void loadAndDecryptConfigFile() throws IOException {
        final SecretKey secretKey = ConfigEncryptor.loadAESKeyFromFile(keyFile);
        properties = ConfigEncryptor.decryptConfig(secretKey, confFile);
    }

    /**
     * @param keyFile Path of the key file to be used for decrypting the configuration file.
     */
    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }

    /**
     * @param confFile Path of the configuration file.
     */
    public void setConfFile(String confFile) {
        this.confFile = confFile;
    }

    /**
     * @return Path of the key file used for decrypting the configuration file.
     */
    public String getKeyFile() {
        return keyFile;
    }

    /**
     * @return Path of the configuration file used for starting the app.
     */
    public String getConfFile() {
        return confFile;
    }

    /**
     * @return Decrypted configuration files as Properties object
     */
    public Properties getProperties() {
        return properties;
    }
}
