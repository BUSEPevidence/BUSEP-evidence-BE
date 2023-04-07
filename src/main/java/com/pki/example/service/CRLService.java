package com.pki.example.service;

import com.pki.example.keystores.KeyStoreReader;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class CRLService {


    private static KeyStoreReader keyStoreReader;
    public static X509CRL createEmptyCRL(
            PrivateKey caKey,
            String sigAlg,
            X509Certificate caCert)
            throws IOException, GeneralSecurityException, OperatorCreationException
    {
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(),
                calculateDate(0));


        crlGen.setNextUpdate(calculateDate(24 * 7));


        // add extensions to CRL
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();


        crlGen.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(caCert));


        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(caKey);


        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");


        return converter.getCRL(crlGen.build(signer));
    }

    public X509CRL getCRL(String path){
        try {
            FileInputStream crlStream = new FileInputStream(path);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
            crlStream.close();
            return crl;
        }
        catch (Exception e) {
            e.getMessage();
        }
        return null;
    }

    public void revokeCertificate(String CRLKeyStore, X509Certificate certificate,PrivateKey caKey,String sigAlg){
        try {
        X509CRL crl = getCRL("src/main/resources/static/" + CRLKeyStore + "CRL.jks");
        crl = addRevocationToCRL(caKey,sigAlg,crl,certificate);
        saveCRLToFile(crl,"src/main/resources/static/" + CRLKeyStore + "CRL.jks");
        CRLService crlService = new CRLService();
    }
    catch (Exception e){
        e.getMessage();
    }
    }

    public X509CRL addRevocationToCRL(
            PrivateKey caKey,
            String sigAlg,
            X509CRL crl,
            X509Certificate certToRevoke)
            throws IOException, GeneralSecurityException, OperatorCreationException
    {
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(crl);


        crlGen.setNextUpdate(calculateDate(24 * 7));


        // add revocation
        ExtensionsGenerator extGen = new ExtensionsGenerator();


        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);


        extGen.addExtension(Extension.reasonCode, false, crlReason);




        crlGen.addCRLEntry(certToRevoke.getSerialNumber(),
                new Date(), extGen.generate());


        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(caKey);


        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");


        return converter.getCRL(crlGen.build(signer));
    }

    public static void saveCRLToFile(X509CRL crl, String filename) throws IOException {
        FileOutputStream outStream = new FileOutputStream(filename);
        try {
            outStream.write(crl.getEncoded());
            outStream.close();
        }
        catch (Exception e)
        {
            e.getMessage();
        }
    }

    public static Date calculateDate(int hoursInFuture)
    {
        long secs = System.currentTimeMillis() / 1000;


        return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
    }
}
