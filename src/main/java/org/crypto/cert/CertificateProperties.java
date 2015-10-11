package org.crypto.cert;

import com.google.common.base.Strings;

public class CertificateProperties {

    private final String dn;
    private final long expiryInMilliSeconds;
    private final boolean saveCertificate;
    private final String certificateFileName;
    private final String filePath;
    private final String subjectiveAlternateName;

    private CertificateProperties(final String dn, final long expiryInMilliSeconds, final boolean saveCertificate,
                                  final String certificateFileName,final String filePath, final String subjectiveAlternateName) {
        this.dn = dn;
        this.expiryInMilliSeconds = expiryInMilliSeconds;
        this.saveCertificate = saveCertificate;
        this.certificateFileName = certificateFileName;
        this.filePath = filePath;
        this.subjectiveAlternateName = subjectiveAlternateName;
    }

    public String dn(){
        return this.dn;
    }

    public long expiryInMilliSeconds(){
        return this.expiryInMilliSeconds;
    }

    public boolean saveCertificate(){
        return this.saveCertificate;
    }

    public String filePath(){
        return this.filePath;
    }

    public String certificateFileName(){
        return this.certificateFileName;
    }

    public String subjectiveAlternateName(){
        return this.subjectiveAlternateName;
    }

    public static CertificatePropertiesBuilder builder(){
        return new CertificatePropertiesBuilder();
    }

    public static class CertificatePropertiesBuilder{
        private String dn;
        private long expiryInMilliSeconds;
        private boolean saveCertificate;
        private String filePath;
        private String certificateFileName;
        private String subjectiveAlternateName;

        public CertificatePropertiesBuilder withDn(final String dn){
            this.dn = dn;
            return this;
        }

        public CertificatePropertiesBuilder withExpiryInMillSeconds(final long expiryInMilliSeconds){
            this.expiryInMilliSeconds = expiryInMilliSeconds;
            return this;
        }

        public CertificatePropertiesBuilder withSaveCertificate(final boolean saveCertificate){
            this.saveCertificate = saveCertificate;
            return this;
        }

        public CertificatePropertiesBuilder withFileLocation(final String filePath){
            this.filePath = filePath;
            return this;
        }

        public CertificatePropertiesBuilder withCertificateFileName(final String certificateFileName){
            this.certificateFileName = certificateFileName;
            return this;
        }

        public CertificatePropertiesBuilder withSubjectiveAlternateName(final String subjectiveAlternateName){
            this.subjectiveAlternateName = subjectiveAlternateName;
            return this;
        }

        public CertificateProperties build(){
            validate();
            return new CertificateProperties(dn, expiryInMilliSeconds, saveCertificate, certificateFileName ,
                    filePath, subjectiveAlternateName);
        }

        private void validate(){
            if(saveCertificate && (Strings.isNullOrEmpty(filePath) ||
                    Strings.isNullOrEmpty(certificateFileName))){
                throw new IllegalArgumentException("File Path or certificate file name cannot be null");
            }
        }
    }
}
