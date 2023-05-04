package com.pki.example;

import com.pki.example.certificates.CertificateExample;
import com.pki.example.controller.AdminController;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import com.pki.example.service.CRLService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationContextFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.io.FileInputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

@SpringBootApplication
@EnableAsync
@EnableScheduling
@EnableJpaRepositories
public class ExampleApplication {

	private static CertificateExample certExample;

	private static KeyStoreReader keyStoreReader;

	private static KeyStoreWriter keyStoreWriter;

	private static ApplicationContext context;
	private static AdminController adminController = new AdminController();

	public static void main(String[] args) throws Exception {
		context = SpringApplication.run(ExampleApplication.class, args);
		//adminController.genCA(context);
		keyStoreReader = (KeyStoreReader) context.getBean("keyStoreReader");
		keyStoreWriter = (KeyStoreWriter) context.getBean("keyStoreWriter");
		certExample = (CertificateExample) context.getBean("certificateExample");
//
		com.pki.example.data.Certificate certificate = certExample.getCertificate();
//		System.out.println("Novi sertifikat:");
//		System.out.println(certificate.getX509Certificate());
//
//		// Inicijalizacija fajla za cuvanje sertifikata
//		System.out.println("Cuvanje certifikata u jks fajl:");
//		keyStoreWriter.loadKeyStore("src/main/resources/static/example.jks",  "password".toCharArray());
//		PrivateKey pk = certificate.getIssuer().getPrivateKey();
//		keyStoreWriter.write("cert1", pk, "password".toCharArray(), certificate.getX509Certificate());
//		keyStoreWriter.saveKeyStore("src/main/resources/static/example.jks",  "password".toCharArray());
//		System.out.println("Cuvanje certifikata u jks fajl zavrseno.");

		//System.out.println("Ucitavanje sertifikata iz jks fajla:");
		//Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/example.jks", "password", "cert1");
		//System.out.println(loadedCertificate);

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(2048, random);
		PrivateKey PrivK = keyGen.generateKeyPair().getPrivate();

		//Kreiranje nove CRL liste:
		X509CRL crl = CRLService.createEmptyCRL(PrivK,"SHA256WithRSAEncryption",certificate.getX509Certificate());
		CRLService.saveCRLToFile(crl,"src/main/resources/static/CRL.jks");

		CRLService crlService = new CRLService();
	}

}
