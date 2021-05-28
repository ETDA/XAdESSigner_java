package sign;

import java.security.cert.X509Certificate;
import java.util.List;

import xades4j.providers.impl.KeyStoreKeyingDataProvider.SigningCertSelector;

public class FirstCertificateSelector implements SigningCertSelector {

	@Override
	public X509Certificate selectCertificate(List<X509Certificate> availableCertificates) {
		// TODO Auto-generated method stub
		return availableCertificates.get(0);
	}

}
