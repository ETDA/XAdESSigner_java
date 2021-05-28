package sign;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import xades4j.XAdES4jException;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;

import pkcs.*;

public class XadesBESController {
	//KeyingDataProvider kp;
	//String fileName;
	//String path;
	//String desPath;

	public KeyStore loadKeyStore()
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keystore = KeyStore.getInstance("Windows-MY");
		FileInputStream fis = new FileInputStream("C:\\Windows\\System32\\eTPKCS11.dll");
		keystore.load(fis, "frontis#1234".toCharArray());
		return keystore;
	}
	
	public Document getSign(Document document, KeyingDataProvider keyingDataProvider, DigestAlgorithm digestAlgorithm) throws XAdES4jException, IOException {

		Element elementToSign = document.getDocumentElement();
		
		String digestAlgorithmText = null;
		switch(digestAlgorithm) {
			case SHA256:
				digestAlgorithmText = "SHA256";
				break;
			case SHA384:
				digestAlgorithmText = "SHA364";
				break;
			case SHA512:
				digestAlgorithmText = "SHA512";
				break;
			default:
				digestAlgorithmText = "SHA256";
		}
		
		AlgorithmsProviderEx ap = new AlgorithmProviderImp(digestAlgorithmText);
		XadesSigningProfile p = new XadesBesSigningProfile(keyingDataProvider);
		p.withAlgorithmsProviderEx(ap);
		XadesSigner signer = p.newSigner();
		DataObjectDesc obj = new DataObjectReference(
				elementToSign.hasAttribute("Id") ? '#' + elementToSign.getAttribute("Id") : "")
						.withTransform(new EnvelopedSignatureTransform());
		XadesSignatureResult result = signer.sign(new SignedDataObjects(obj), document.getDocumentElement());
		XMLSignature signature = result.getSignature();
		return signature.getDocument();
	}
	
	public XadesBESController(String inputFileName, String outputFileName, KeyingDataProvider keyingDataProvider,  DigestAlgorithm digestAlgorithm) throws Exception {
		
		File inputFile = new File(inputFileName);
		if (!inputFile.isFile() || !inputFileName.endsWith(".xml")) {
			throw new Exception("Input must be xml file");
		} 
		
		Document doc = getSign(DocumentIOHelper.getXMLDocumentByPath(inputFileName), keyingDataProvider, digestAlgorithm);
		DocumentIOHelper.writeSignedFile(doc, outputFileName);
	}

}
