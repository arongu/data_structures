package loader;

import java.util.List;
import java.util.Properties;

public class ConfigField {
    public final String key;
    public final boolean sensitive;

    public ConfigField(final String key, final boolean sensitive) {
        this.key = key;
        this.sensitive = sensitive;
    }
    
    public ConfigField(final String key) {
        this(key,false);
    }

    public static Properties toProperties(final List<ConfigField> configFields, final Properties source) {
        final Properties collected = new Properties();

        for ( ConfigField cf : configFields ) {
            if ( source.containsKey(cf.key) ) {
                collected.setProperty(cf.key, source.getProperty(cf.key));
            }
        }

        return collected;
    }
}