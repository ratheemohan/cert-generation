package org.crypto.cert.keystore;

public class KeyStoreProperties {
    private final String fileName;
    private final String filePath;
    private final String password;

    private KeyStoreProperties(final String fileName, final String filePath, final String password) {
        this.fileName = fileName;
        this.filePath = filePath;
        this.password = password;
    }

    public String fileName() {
        return fileName;
    }

    public String filePath() {
        return filePath;
    }

    public String password() {
        return password;
    }

    public static class KeyStorePropertiesBuilder {

        private String fileName;
        private String filePath;
        private String password;

        public KeyStorePropertiesBuilder withFileName(final String fileName) {
            this.fileName = fileName;
            return this;
        }

        public KeyStorePropertiesBuilder withFilePath(final String filePath) {
            this.filePath = filePath;
            return this;
        }

        public KeyStorePropertiesBuilder withPassword(final String password) {
            this.password = password;
            return this;
        }

        public KeyStoreProperties build() {
            return new KeyStoreProperties(fileName, filePath, password);
        }

    }
}
