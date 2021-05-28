package sign;

import java.security.cert.X509Certificate;

import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyEntryPasswordProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyStorePasswordProvider;

public class DirectPasswordProvider implements KeyStorePasswordProvider, KeyEntryPasswordProvider {
	private char[] password;
	public DirectPasswordProvider(String pwd) {
		// TODO Auto-generated constructor stub
		this.password = pwd.toCharArray();
	}
	@Override
	public char[] getPassword(String entryAlias, X509Certificate entryCert) {
		// TODO Auto-generated method stub
		return password;
	}

	@Override
	public char[] getPassword() {
		// TODO Auto-generated method stub
		return password;
	}

}
