package sign;

import java.io.File;
import java.io.IOException;

import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import timestamp.TSAAuthenticationType;
import timestamp.TimeStamp;
import timestamp.TimeStampType;
import xades4j.XAdES4jException;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.production.XadesTSigningProfile;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.TSAHttpData;

public class XadesTController {
	
	public XadesTController(String inputFileName, String outputFileName, KeyingDataProvider keyingDataProvider,
			DigestAlgorithm digestAlgorithm, TimeStamp timeStamp) throws Exception {
		// TODO Auto-generated constructor stub
		File inputFile = new File(inputFileName);
		if (!inputFile.isFile() || !inputFileName.endsWith(".xml")) {
			throw new Exception("Input must be xml file");
		} 
		
		Document doc = getSign(DocumentIOHelper.getXMLDocumentByPath(inputFileName), keyingDataProvider, digestAlgorithm, timeStamp);
		DocumentIOHelper.writeSignedFile(doc, outputFileName);
	}
	
	public Document getSign(Document doc, KeyingDataProvider keyingDataProvider,
			DigestAlgorithm digestAlgorithm, TimeStamp timeStamp) throws Exception {
		
		String digestAlgorithmText = null;
		switch(digestAlgorithm) {
			case SHA256:
				digestAlgorithmText = "SHA256";
				break;
			case SHA384:
				digestAlgorithmText = "SHA384";
				break;
			case SHA512:
				digestAlgorithmText = "SHA512";
				break;
			default:
				digestAlgorithmText = "SHA256";
		}
		
		AlgorithmsProviderEx ap = new AlgorithmProviderImp(digestAlgorithmText);
		Element elementToSign = doc.getDocumentElement();
		XadesSigner signer = new XadesTSigningProfile(keyingDataProvider).withBinding(TSAHttpData.class, getTSAHttpData(timeStamp))
				.withAlgorithmsProviderEx(ap).newSigner();
		DataObjectDesc obj = new DataObjectReference(
				elementToSign.hasAttribute("Id") ? '#' + elementToSign.getAttribute("Id") : "")
						.withTransform(new EnvelopedSignatureTransform());
		XadesSignatureResult result = signer.sign(new SignedDataObjects(obj), doc.getDocumentElement());
		XMLSignature signature = result.getSignature();
		return signature.getDocument();
	}
	
	
	private TSAHttpData getTSAHttpData(TimeStamp timeStamp) throws Exception {
		if (timeStamp.getTimeStampingType() != TimeStampType.TSA) {
			throw new Exception("XAdES-T must use timestamp from TSA rather than signer's computer clock");
		}
		
		if (timeStamp.getTSAAuthenticationType() == TSAAuthenticationType.NO_AUTHENTICATION) {
			return new TSAHttpData(timeStamp.getURL());
		} else if (timeStamp.getTSAAuthenticationType() == TSAAuthenticationType.USERNAME_PASSWORD) {
			return new TSAHttpData(timeStamp.getURL(), timeStamp.getUsername(), timeStamp.getPassword());
		} else if (timeStamp.getTSAAuthenticationType() == TSAAuthenticationType.CERTIFICATE) {
			return new TSAHttpData(timeStamp.getURL(), timeStamp.getCertificatePath(), timeStamp.getCertificatePassword());
		}
		else {
			return null;
		}
		
		
	}

}
