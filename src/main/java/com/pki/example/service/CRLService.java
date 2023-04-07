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
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
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
    public void revCert(String CRLKeyStore, X509Certificate certificate,PrivateKey caKey,String sigAlg){
        try {
            System.out.println("Usao u revCert");
            System.out.println(certificate);
            AdminService adminService = new AdminService();
            X509CRL crl = getCRL("src/main/resources/static/" + CRLKeyStore + "CRL.jks");
            crl = addRevocationToCRL(caKey,sigAlg,crl,certificate);
            saveCRLToFile(crl,"src/main/resources/static/" + CRLKeyStore + "CRL.jks");
            CRLService crlService = new CRLService();
            crlService.checkRevoked(certificate);
        }
        catch (Exception e){
            e.getMessage();
        }
    }

    public void revokeCertificate(String CRLKeyStore, X509Certificate certificate,PrivateKey caKey,String sigAlg){
        try {
            AdminService adminService = new AdminService();
            String crlFilePath = "src/main/resources/static/" + CRLKeyStore + "CRL.jks";
            X509CRL crl = getCRL(crlFilePath);
            crl = addRevocationToCRL(caKey, sigAlg, crl, certificate);
            saveCRLToFile(crl, crlFilePath);
            CRLService crlService = new CRLService();
            X509Certificate cert = adminService.printCertificateInfo(certificate);


    }
    catch (Exception e){
        e.getMessage();
    }
    }
    public void checkRevoked(X509Certificate cert)
    {
        try {
            FileInputStream fileInputStream = new FileInputStream("src/main/resources/static/CRL.jks");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CRL crl = cf.generateCRL(fileInputStream);
            fileInputStream.close();

            // Access the CRL contents and perform checks as needed
            // For example, you can check if the certificate you're interested in is revoked
            if (crl.isRevoked(cert)) {
                System.out.println("Certificate is revoked.");
            } else {
                System.out.println("Certificate is not revoked.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
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
