package sign;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;

import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;

public class AlgorithmProviderImp extends DefaultAlgorithmsProviderEx {
	String algorithm;

	public AlgorithmProviderImp(String algorithm) {
		this.algorithm = algorithm;
	}
	public AlgorithmProviderImp() {
		this.algorithm = "SHA256";
	}
	@Override
	public String getDigestAlgorithmForDataObjsReferences() {

		if (this.algorithm.equals("SHA384")) {
			return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384;
		} else if (this.algorithm.equals("SHA512")) {
			return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
		} else {
			return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
		}

	}

	@Override
	public String getDigestAlgorithmForReferenceProperties() {
		if (this.algorithm.equals("SHA384")) {
			return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384;
		} else if (this.algorithm.equals("SHA512")) {
			return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
		} else {
			return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
		}
	}

	@Override
	public String getDigestAlgorithmForTimeStampProperties() {
		if (this.algorithm.equals("SHA384")) {
			return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384;
		} else if (this.algorithm.equals("SHA512")) {
			return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
		} else {
			return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
		}
	}

	@Override
	public Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException {
		if (this.algorithm.equals("SHA384")) {
			return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384);
		} else if (this.algorithm.equals("SHA512")) {
			return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
		} else {
			return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
		}
	}
}
