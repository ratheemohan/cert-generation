package org.crypto.cert;

public class CertificateProperties {

    private final String dn;
    private final long expiryDays;

    private CertificateProperties(final String dn, final long expiryDays) {
        this.dn = dn;
        this.expiryDays = expiryDays;
    }

    public String dn(){
        return this.dn;
    }

    public long expiryDays(){
        return this.expiryDays;
    }

    public static CertificatePropertiesBuilder builder(){
        return new CertificatePropertiesBuilder();
    }

    public static class CertificatePropertiesBuilder{
        private String dn;
        private long expiryDays;

        public CertificatePropertiesBuilder withDn(final String dn){
            this.dn = dn;
            return this;
        }

        public CertificatePropertiesBuilder withExpiryDays(final long expiryDays){
            this.expiryDays = expiryDays;
            return this;
        }

        public CertificateProperties build(){
            return new CertificateProperties(dn, expiryDays);
        }
    }
}
