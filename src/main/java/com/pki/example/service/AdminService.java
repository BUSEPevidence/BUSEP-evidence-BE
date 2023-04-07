package com.pki.example.service;

import com.pki.example.ExampleApplication;
import com.pki.example.certificates.CertificateExample;
import com.pki.example.certificates.CertificateGenerator;
import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.UUID;
import java.util.GregorianCalendar;

@Service
public class AdminService {
    private static CertificateExample certExample;

    private static KeyStoreReader keyStoreReader;

    private static KeyStoreWriter keyStoreWriter;

    private static ApplicationContext context;


    public com.pki.example.data.Certificate generateCertificate(String keyStoreFileName,String certificateName,String keyStorePassword,com.pki.example.data.Certificate cert)
    {
        keyStoreReader = new KeyStoreReader();
        keyStoreWriter = new KeyStoreWriter();
        //certExample = (CertificateExample) context.getBean("certificateExample");

        com.pki.example.data.Certificate certificate = cert;
        System.out.println("Novi sertifikat:");
        System.out.println(certificate.getX509Certificate());

        // Inicijalizacija fajla za cuvanje sertifikata
        System.out.println("Cuvanje certifikata u jks fajl:");
        keyStoreWriter.loadKeyStore("src/main/resources/static/" + keyStoreFileName + ".jks",  keyStorePassword.toCharArray());
        PrivateKey pk = certificate.getIssuer().getPrivateKey();
        keyStoreWriter.write(certificateName, pk, keyStorePassword.toCharArray(), certificate.getX509Certificate());
        keyStoreWriter.saveKeyStore("src/main/resources/static/"  + keyStoreFileName + ".jks",  keyStorePassword.toCharArray());
        System.out.println("Cuvanje certifikata u jks fajl zavrseno.");
        return certificate;



    }
    public Certificate readCertificateFromKeyStore(String keyStoreFileName,String password,String alias)
    {
        keyStoreReader = (KeyStoreReader) context.getBean("keyStoreReader");
        keyStoreWriter = (KeyStoreWriter) context.getBean("keyStoreWriter");
        certExample = (CertificateExample) context.getBean("certificateExample");

        System.out.println("Ucitavanje sertifikata iz jks fajla:");
        Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/" + keyStoreFileName + ".jks", password, alias);
        System.out.println(loadedCertificate);

        return loadedCertificate;
    }

    public void checkValidationOfSign(String keyStoreFileName,String password,String alias,
                                      PublicKey publicKey)
    {
        keyStoreReader = new KeyStoreReader();
        keyStoreWriter = new KeyStoreWriter();;
       // com.pki.example.data.Certificate certificate = certificatte;
        Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/" + keyStoreFileName + ".jks", password, alias);
        System.out.println(loadedCertificate);
        System.out.println("Provera potpisa:");
        // to do
        try {
            loadedCertificate.verify(publicKey);
            ((X509Certificate) loadedCertificate).checkValidity();
            System.out.println("Certificate is valid.");
        } catch (CertificateExpiredException e) {
            System.out.println("Certificate has expired.");
        } catch (CertificateNotYetValidException e) {
            System.out.println("Certificate is not yet valid.");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
          }
        catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
    public Subject generateSubject(String CN,String Surname,String Name,String O,String OU,String C,String Email,String UID) {
        KeyPair keyPairSubject = generateKeyPair();

        //klasa X500NameBuilder pravi X500Name objekat koji predstavlja podatke o vlasniku
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, CN);
        builder.addRDN(BCStyle.SURNAME, Surname);
        builder.addRDN(BCStyle.GIVENNAME, Name);
        builder.addRDN(BCStyle.O, O);
        builder.addRDN(BCStyle.OU, OU);
        builder.addRDN(BCStyle.C, C);
        builder.addRDN(BCStyle.E, Email);
        //UID (USER ID) je ID korisnika
        builder.addRDN(BCStyle.UID, UID);

        return new Subject(keyPairSubject.getPublic(), builder.build());
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
    public Issuer generateIssuer(String CN,String Surname,String Name,String O,String OU,String C,String Email,String UID) {
        KeyPair kp = generateKeyPair();
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, CN);
        builder.addRDN(BCStyle.SURNAME, Surname);
        builder.addRDN(BCStyle.GIVENNAME, Name);
        builder.addRDN(BCStyle.O, O);
        builder.addRDN(BCStyle.OU, OU);
        builder.addRDN(BCStyle.C, C);
        builder.addRDN(BCStyle.E, Email);
        //UID (USER ID) je ID korisnika
        builder.addRDN(BCStyle.UID, UID);
        //Kreiraju se podaci za issuer-a, sto u ovom slucaju ukljucuje:
        // - privatni kljuc koji ce se koristiti da potpise sertifikat koji se izdaje
        // - podatke o vlasniku sertifikata koji izdaje nov sertifikat
        return new Issuer(kp.getPrivate(), kp.getPublic(), builder.build());
    }
    public com.pki.example.data.Certificate getEndEntityCertificate(Issuer issuerData,Subject subjectData,String startValidDate,String endValidDate) {

        try {
            Issuer issuer = issuerData;
            Subject subject = subjectData;

            //Datumi od kad do kad vazi sertifikat
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            Date startDate = sdf.parse(startValidDate);
            Date endDate = sdf.parse(endValidDate);

            X509Certificate certificate = CertificateGenerator.generateCertificate(subject,
                    issuer, startDate, endDate, "1");

            return new com.pki.example.data.Certificate(subject, issuer,
                    "1", startDate, endDate, certificate);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return null;
    }
    public com.pki.example.data.Certificate getSelfSignedCertificate(Issuer issuerData,String startValidDate,String endValidDate) {

        try {
            Issuer issuer = issuerData;
            Subject subject = new Subject();

            //Datumi od kad do kad vazi sertifikat
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            Date startDate = sdf.parse(startValidDate);
            Date endDate = sdf.parse(endValidDate);

            X509Certificate certificate = CertificateGenerator.generateCertificate(subject,
                    issuer, startDate, endDate, "1");

            return new com.pki.example.data.Certificate(subject, issuer,
                    "1", startDate, endDate, certificate);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return null;
    }
    public static Date calculateDate(int hoursInFuture)
    {
        long secs = System.currentTimeMillis() / 1000;


        return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
    }
    private static long serialNumberBase = System.currentTimeMillis();


    /**
     * Calculate a serial number using a monotonically increasing value.
     *
     * @return a BigInteger representing the next serial number in the sequence.
     */
    public static synchronized BigInteger calculateSerialNumber()
    {
        return BigInteger.valueOf(serialNumberBase++);
    }
    public static X509Certificate createTrustAnchor(
            KeyPair keyPair, String sigAlg)
            throws OperatorCreationException, CertificateException
    {
        X500Name name = new X500Name("CN=Trust Anchor");


        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                name,
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 365),
                name,
                keyPair.getPublic());


        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(keyPair.getPrivate());


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }
    public static X509Certificate createEndEntity(
            X509Certificate signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey)
            throws CertIOException, OperatorCreationException, CertificateException
    {
        X500Principal subject = new X500Principal("CN=End Entity");


        X509v3CertificateBuilder  certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubjectX500Principal(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                subject,
                certKey);


        certBldr.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,
                        true, new BasicConstraints(false))
                .addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature));


        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(signerKey);


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }
    public static X509Certificate createCACertificate(
            X509Certificate signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey, int followingCACerts)
            throws GeneralSecurityException,
            OperatorCreationException, CertIOException
    {
        X500Principal subject = new X500Principal("CN=Certificate Authority");


        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubjectX500Principal(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 60),
                subject,
                certKey);


        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();


        certBldr.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,
                        true, new BasicConstraints(followingCACerts))
                .addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.keyCertSign
                                | KeyUsage.cRLSign));


        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(signerKey);


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }
    public PublicKey getIssuerFromKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream inputStream = new FileInputStream("src/main/resources/static/example.jks"); // replace with your KeyStore source
        String password = "password"; // replace with your KeyStore password
        keyStore.load(inputStream, password.toCharArray());
        String alias = "cert8"; // replace with the alias of the certificate for which you want to get issuer information
        Certificate certificate = keyStore.getCertificate(alias);
        PublicKey issuerPublicKey = null;
        if (certificate instanceof X509Certificate) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            X500Principal issuerPrincipal = x509Certificate.getIssuerX500Principal();

            // Retrieve the issuer's public key from the KeyStore
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String keyStoreAlias = aliases.nextElement();
                Certificate keyStoreCertificate = keyStore.getCertificate(keyStoreAlias);
                if (keyStoreCertificate instanceof X509Certificate) {
                    X509Certificate keyStoreX509Certificate = (X509Certificate) keyStoreCertificate;
                    X500Principal keyStoreIssuerPrincipal = keyStoreX509Certificate.getIssuerX500Principal();
                    if (issuerPrincipal.equals(keyStoreIssuerPrincipal)) {
                        issuerPublicKey = keyStoreX509Certificate.getPublicKey();
                        break;
                    }
                }
            }


        }
        return issuerPublicKey;
    }

}
