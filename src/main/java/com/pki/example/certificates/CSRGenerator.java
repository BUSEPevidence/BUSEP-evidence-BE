package com.pki.example.certificates;

import java.security.PrivateKey;

import com.pki.example.certificates.CertificateExample;
import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;


public class CSRGenerator {

    public PKCS10CertificationRequest csr;
    public CertificateExample kg;

    public CSRGenerator() {

    }

    public CSRGenerator(Subject subjectData) {

    }

    public CSRGenerator(PKCS10CertificationRequest csr) {
        super();
        this.csr = csr;
    }

    public PKCS10CertificationRequest getCsr() {
        return csr;
    }

    public void setCsr(PKCS10CertificationRequest csr) {
        this.csr = csr;
    }

    //mogu i da se dodaju ekstenzije u csr - al mozda mozemo da izbegnemo pogadjanjem specificnih endpointova
    public static PKCS10CertificationRequest generateCSR(Subject subjectData, Issuer issuer) throws OperatorCreationException {
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subjectData.getX500Name(), subjectData.getPublicKey());

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        contentSignerBuilder = contentSignerBuilder.setProvider("BC");
        ContentSigner contentSigner = contentSignerBuilder.build(issuer.getPrivateKey());
        PKCS10CertificationRequest csr = p10Builder.build(contentSigner);
        return csr;
    }


}
