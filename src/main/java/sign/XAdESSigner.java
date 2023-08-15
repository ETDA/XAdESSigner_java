package sign;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import io.FileSpecification;
import pkcs.*;
import timestamp.TimeStamp;

import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;

public class XAdESSigner {
	public XAdESSigner() {
		
	}
	
	public void signBESOnce(String inputFilePath, String outputFilePath, IPKCSInstance pkcs, DigestAlgorithm digestAlgorithm) throws Exception {
		if (pkcs instanceof PKCS12Instance) {
			new XadesBESController(inputFilePath, outputFilePath, getKeyStore((PKCS12Instance)pkcs), digestAlgorithm);
		} else if (pkcs instanceof PKCS11Instance) {
			new XadesBESController(inputFilePath, outputFilePath, getKeyStore((PKCS11Instance)pkcs), digestAlgorithm);
		} else {
			throw new Exception("Unknown PKCS configuration");
		}
	}
	
	public void signBESMultiple(String inputFolderPath, String outputFolderPath, String outputSuffix, IPKCSInstance pkcs, DigestAlgorithm digestAlgorithm) throws Exception, Exception {
		java.util.List<FileSpecification> fileSpecList = getFileFromFolder(inputFolderPath);
		KeyingDataProvider keyingDataProvider = null;
		if (pkcs instanceof PKCS12Instance) {
			keyingDataProvider = getKeyStore((PKCS12Instance)pkcs);
		} else if (pkcs instanceof PKCS11Instance) {
			keyingDataProvider = getKeyStore((PKCS11Instance)pkcs);
		} else {
			throw new Exception("Unknown PKCS configuration");
		}
		
		for(FileSpecification fileSpec : fileSpecList)  {
			String inputFilePath = fileSpec.getFullFilePath();
			String outputFilePath = null;
			if (outputSuffix != null) {
				outputFilePath = outputFolderPath + "/" + fileSpec.getFileNameWithoutExtension() + outputSuffix + "." + fileSpec.getFileExtension();
			} else {
				outputFilePath = outputFolderPath + "/" + fileSpec.getFileNameWithoutExtension() + "." + fileSpec.getFileExtension();
			}
			System.out.println("Signing: " + fileSpec.getFileNameWithExtension());
			
			new XadesBESController(inputFilePath, outputFilePath, keyingDataProvider, digestAlgorithm);
			/*
			if (pkcs instanceof PKCS12Instance) {
				new XadesBESController(inputFilePath, outputFilePath, getKeyStore((PKCS12Instance)pkcs), digestAlgorithm);
			} else if (pkcs instanceof PKCS11Instance) {
				new XadesBESController(inputFilePath, outputFilePath, getKeyStore((PKCS11Instance)pkcs), digestAlgorithm);
			} else {
				throw new Exception("Unknown PKCS configuration");
			}
			*/
		}
	}
	
	public void signTOnce(String inputFilePath, String outputFilePath, IPKCSInstance pkcs, DigestAlgorithm digestAlgorithm, TimeStamp timeStamp) throws Exception {
		//XadesBESController signBES = new XadesBESController("./XMLFolder", "PKCS12", "trustStore/tsa.p12", "1234");
		if (pkcs instanceof PKCS12Instance) {
			new XadesTController(inputFilePath, outputFilePath, getKeyStore((PKCS12Instance)pkcs), digestAlgorithm, timeStamp);
		} else if (pkcs instanceof PKCS11Instance) {
			new XadesTController(inputFilePath, outputFilePath, getKeyStore((PKCS11Instance)pkcs), digestAlgorithm, timeStamp);
		} else {
			throw new Exception("Unknown PKCS configuration");
		}
		
	}
	
	public void signTMultiple(String inputFolderPath, String outputFolderPath, String outputSuffix, IPKCSInstance pkcs, DigestAlgorithm digestAlgorithm, TimeStamp timeStamp) throws Exception, Exception {
		java.util.List<FileSpecification> fileSpecList = getFileFromFolder(inputFolderPath);
		KeyingDataProvider keyingDataProvider = null;
		if (pkcs instanceof PKCS12Instance) {
			keyingDataProvider = getKeyStore((PKCS12Instance)pkcs);
		} else if (pkcs instanceof PKCS11Instance) {
			keyingDataProvider = getKeyStore((PKCS11Instance)pkcs);
		}
		
		for(FileSpecification fileSpec : fileSpecList)  {
			String inputFilePath = fileSpec.getFullFilePath();
			String outputFilePath = null;
			if (outputSuffix != null) {
				outputFilePath = outputFolderPath + "/" + fileSpec.getFileNameWithoutExtension() + outputSuffix + "." + fileSpec.getFileExtension();
			} else {
				outputFilePath = outputFolderPath + "/" + fileSpec.getFileNameWithoutExtension() + "." + fileSpec.getFileExtension();
			}
			System.out.println("Signing: " + fileSpec.getFileNameWithExtension());
			new XadesTController(inputFilePath, outputFilePath, keyingDataProvider, digestAlgorithm, timeStamp);
			/*
			if (pkcs instanceof PKCS12Instance) {
				new XadesTController(inputFilePath, outputFilePath, getKeyStore((PKCS12Instance)pkcs), digestAlgorithm, timeStamp);
			} else if (pkcs instanceof PKCS11Instance) {
				new XadesTController(inputFilePath, outputFilePath, getKeyStore((PKCS11Instance)pkcs), digestAlgorithm, timeStamp);
			} else {
				throw new Exception("Unknown PKCS configuration");
			}
			*/
			System.out.println("Wait for 5 seconds...");
			TimeUnit.SECONDS.sleep(5);
		}
	}
	
	private KeyingDataProvider getKeyStore(PKCS11Instance pkcs11Instance) throws Exception {
		
		String pkcs11Config = String.format("name=%s\nlibrary=%s", pkcs11Instance.getTokenName(), pkcs11Instance.getLibraryPath());

		java.io.ByteArrayInputStream pkcs11ConfigStream = new java.io.ByteArrayInputStream(pkcs11Config.getBytes());
		sun.security.pkcs11.SunPKCS11 provider = new sun.security.pkcs11.SunPKCS11(pkcs11ConfigStream);
		java.security.Security.addProvider(provider);

		String pin = pkcs11Instance.getPin();
		KeyStore keyStore=KeyStore.getInstance("PKCS11",provider);
		keyStore.load(null, pin.toCharArray());
		
		java.util.Enumeration<String> aliases = keyStore.aliases();
		String alias = null;
		char[] passwordCharArr = pkcs11Instance.getKeyStorePassword().toCharArray();		 
		
		boolean isKeyStoreFound = false;
		PrivateKey pk = null;
		Certificate[] chain = null;
		X509Certificate certificate = null;
		
		System.out.println("\tCertificate subject found in X509Principle:");
		
		while (aliases.hasMoreElements()) {
		    alias = aliases.nextElement();
		    
		    certificate = (X509Certificate) keyStore.getCertificate(alias);
		    System.out.println("\t\t" + certificate.getSubjectDN().getName());
	        if (certificate.getSubjectDN().getName().contains(pkcs11Instance.getSearchPhase())) {
	        	pk = (PrivateKey) keyStore.getKey(alias, passwordCharArr);
	            chain = keyStore.getCertificateChain(alias);
	            isKeyStoreFound = true;
	        	break;
	        }
	    }
		
		if (isKeyStoreFound == false) {
        	throw new Exception("KeyStore was not found.");
        }
		
		KeyingDataProvider keyingDataProvider = new DirectKeyingDataProvider((X509Certificate) certificate,
				(PrivateKey) pk);
		
		return keyingDataProvider;
	}
	
	private KeyingDataProvider getKeyStore(PKCS12Instance pkcs12Instance) throws KeyStoreException {
		return  new FileSystemKeyStoreKeyingDataProvider("PKCS12", pkcs12Instance.getFilePath(),
				new FirstCertificateSelector(), new DirectPasswordProvider(pkcs12Instance.getKeyStorePassword()),
				new DirectPasswordProvider(pkcs12Instance.getKeyStorePassword()), false);
	}
	
	private java.util.List<FileSpecification> getFileFromFolder(String folderPath) {
		
		java.util.List<FileSpecification> fileSpecList = new java.util.ArrayList<FileSpecification>();
		
		File dir = new File(folderPath);
		File[] directoryListing = dir.listFiles();
		if (directoryListing != null) {
			for (File file : directoryListing) {
				FileSpecification fileSpecification = new FileSpecification();
				fileSpecification.setFullFilePath(file.getAbsolutePath());
				fileSpecification.setFileNameWithExtension(file.getName());
				fileSpecification.setFileNameWithoutExtension(file.getName().split("\\.")[0]);
				fileSpecification.setFileExtension(file.getName().split("\\.")[1]);
				fileSpecList.add(fileSpecification);
			}
		}
		return fileSpecList;
	}
}
