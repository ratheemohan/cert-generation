package org.crypto.cert;

import sun.security.x509.*;

import java.io.FileOutputStream;
import java.security.cert.*;
import java.security.*;
import java.math.BigInteger;
import java.util.Date;
import java.io.IOException;

public class GenerateCertificate {

    private final static String CERTIFICATE_GENERATION_ALGORITHM = "SHA1withRSA";

    public GenerateCertificate(){

    }

    public X509Certificate generateCertificate(final CertificateProperties certificateProperties) throws Exception{
        final KeyPair keyPair = certificateKeyPair();
        final PrivateKey privkey = keyPair.getPrivate();
        final X509CertInfo info = new X509CertInfo();
        final Date from = new Date();
        final Date to = new Date(from.getTime() + certificateProperties.expiryDays() * 86400000l);
        final CertificateValidity interval = new CertificateValidity(from, to);
        final BigInteger sn = new BigInteger(64, new SecureRandom());
        final X500Name owner = new X500Name(certificateProperties.dn());

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
        info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        // Sign the cert to identify the algorithm that's used.
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privkey, CERTIFICATE_GENERATION_ALGORITHM);

        // Update the algorithm, and resign.
        algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(privkey, CERTIFICATE_GENERATION_ALGORITHM);

        final FileOutputStream fileOutputStream = new FileOutputStream("/tmp/test.cert");
        fileOutputStream.write(cert.getEncoded());

        return cert;
    }

    private KeyPair certificateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) throws Exception{
        final GenerateCertificate generateCertificate = new GenerateCertificate();
        final CertificateProperties certificateProperties = CertificateProperties.builder()
                .withDn("CN= Meeting Manager, OU=UBS, O=UBS L=CH, C=CH")
                .withExpiryDays(720)
                .build();
        generateCertificate.generateCertificate(certificateProperties);
    }

}
