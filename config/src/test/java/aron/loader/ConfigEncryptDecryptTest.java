package aron.loader;

import org.junit.jupiter.api.Test;

import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class ConfigEncryptDecryptTest {
    static final Properties properties;
    static final List<ConfigField> dbFields;
    static final List<ConfigField> appFields;

    static {
        properties = new Properties();
        properties.setProperty("db_driver", "org.postgresql.Driver");
        properties.setProperty("db_url", "jdbc:postgresql://db100:5432/test_work");
        properties.setProperty("db_user", "robot");
        properties.setProperty("db_password", "secretdbpassword");
        properties.setProperty("app_node_name", "test");
        properties.setProperty("app_max_login_attempts", "15");

        dbFields = new LinkedList<>();
        dbFields.add( new ConfigField("db_driver") );
        dbFields.add( new ConfigField("db_url") );
        dbFields.add( new ConfigField("db_user" ) );
        dbFields.add( new ConfigField("db_password") );
        appFields = new LinkedList<>();
        appFields.add( new ConfigField("app_node_name") );
        appFields.add( new ConfigField("app_max_login_attempts") );
    }

    @Test
    public void toProperties_shouldAddOnlyDbRelatedFields() {
        final Properties dbProperties = ConfigField.toProperties(dbFields, properties);

        assertEquals(4, dbProperties.size());
        assertEquals(dbProperties.getProperty("db_driver"), "org.postgresql.Driver");
        assertEquals(dbProperties.getProperty("db_url"), "jdbc:postgresql://db100:5432/test_work");
        assertEquals(dbProperties.getProperty("db_user"), "robot");
        assertEquals(dbProperties.getProperty("db_password"), "secretdbpassword");
        assertFalse(dbProperties.containsKey("app_node_name"));
        assertFalse(dbProperties.containsKey("app_max_login_attempts"));
    }
}
