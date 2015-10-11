package org.crypto.cert;

import com.google.common.base.Strings;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Paths;
import java.security.cert.*;
import java.security.*;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;

public class GenerateCertificate {

    private final static String CERTIFICATE_GENERATION_ALGORITHM = "SHA256WithRSAEncryption";
    private final static int KEY_SIZE = 1024;

    public GenerateCertificate(){

    }

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public byte[] generateCertificate(final CertificateProperties certificateProperties) throws Exception{
        final KeyPair keyPair = certificateKeyPair();
        final Date startDate = new Date();
        final Date expiryDate = new Date(certificateProperties.expiryInMilliSeconds());
        final BigInteger serialNumber = BigInteger.valueOf(new SecureRandom().nextInt(Integer.MAX_VALUE));
        final PrivateKey caKey = keyPair.getPrivate();
        final X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        final X500Principal subjectName = new X500Principal(certificateProperties.dn());

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(subjectName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(subjectName);
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm(CERTIFICATE_GENERATION_ALGORITHM);

        certGen.addExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(true, 0));
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(keyPair.getPublic()));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(keyPair.getPublic()));
        if (!Strings.isNullOrEmpty(certificateProperties.subjectiveAlternateName())) {
            certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
                    new GeneralName(GeneralName.rfc822Name, "Meeting Manager")));
        }

        final X509Certificate cert = certGen.generate(caKey, "BC");

        if (certificateProperties.saveCertificate()) {
            FileOutputStream fileOutputStream = new FileOutputStream(Paths.get(certificateProperties.filePath(),
                    File.separator, certificateProperties.certificateFileName()).toString());
            fileOutputStream.write(cert.getEncoded());
        }
        return cert.getEncoded();
    }

    private KeyPair certificateKeyPair() throws Exception {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) throws Exception{
        final GenerateCertificate generateCertificate = new GenerateCertificate();
        final Calendar calendar = Calendar.getInstance();
        calendar.set(2020,10,10);
        final CertificateProperties certificateProperties = CertificateProperties.builder()
                .withDn("CN= Meeting Manager, OU=UBS, O=UBS L=CH, C=CH")
                .withExpiryInMillSeconds(calendar.getTimeInMillis())
                .withFileLocation("/tmp/")
                .withCertificateFileName("test.cert")
                .withSaveCertificate(true)
                .build();

        generateCertificate.generateCertificate(certificateProperties);
    }

}
