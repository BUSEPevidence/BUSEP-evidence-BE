package com.pki.example;

import com.pki.example.certificates.CertificateExample;
import com.pki.example.controller.AdminController;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationContextFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

@SpringBootApplication
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

		com.pki.example.data.Certificate certificate = certExample.getCertificate();
		System.out.println("Novi sertifikat:");
		System.out.println(certificate.getX509Certificate());

		// Inicijalizacija fajla za cuvanje sertifikata
		System.out.println("Cuvanje certifikata u jks fajl:");
		keyStoreWriter.loadKeyStore("src/main/resources/static/example.jks",  "password".toCharArray());
		PrivateKey pk = certificate.getIssuer().getPrivateKey();
		keyStoreWriter.write("cert1", pk, "password".toCharArray(), certificate.getX509Certificate());
		keyStoreWriter.saveKeyStore("src/main/resources/static/example.jks",  "password".toCharArray());
		System.out.println("Cuvanje certifikata u jks fajl zavrseno.");

		System.out.println("Ucitavanje sertifikata iz jks fajla:");
		Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/example.jks", "password", "cert1");
		System.out.println(loadedCertificate);

		System.out.println("Provera potpisa:");
		// to do
		try {
			loadedCertificate.verify(certificate.getIssuer().getPublicKey());
			((X509Certificate) loadedCertificate).checkValidity();
				System.out.println("Certificate is valid.");
		} catch (CertificateExpiredException e) {
			System.out.println("Certificate has expired.");
		} catch (CertificateNotYetValidException e) {
			System.out.println("Certificate is not yet valid.");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
			throw new RuntimeException(e);
		}


	}

}
