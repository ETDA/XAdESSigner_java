package timestamp;

public class TimeStamp {
	private TSAAuthenticationType _tsaAuthenticationType;
	private TimeStampType _timeStampType;
	private String _username, _password, _certificatePath, _URL;
	private char[] certificatePassword;
	
	/**
	 * 
	 * @param timeStampingType
	 */
	public TimeStamp(TimeStampType timeStampingType) {
		setTimeStampingType(timeStampingType);
	}
	
	/**
	 * 
	 * @param timeStampingType
	 * @param tsaAuthenticationType
	 */
	public TimeStamp(TimeStampType timeStampingType, String url, TSAAuthenticationType tsaAuthenticationType) {
		setTimeStampingType(timeStampingType);
		setTSAAuthenticationType(tsaAuthenticationType);
		setURL(url);
	}
	
	/**
	 * 
	 * @param timeStampingType
	 * @param tsaAuthenticationType
	 * @param username
	 * @param password
	 */
	public TimeStamp(TimeStampType timeStampingType, String url, TSAAuthenticationType tsaAuthenticationType, String username, String password) {
		setTimeStampingType(timeStampingType);
		setURL(url);
		setTSAAuthenticationType(tsaAuthenticationType);
		setUsername(username);
		setPassword(password);
	}
	
	public TimeStamp(TimeStampType timeStampingType, String url, TSAAuthenticationType tsaAuthenticationType, String certificatePath, char[] certificatePassword) {
		setTimeStampingType(timeStampingType);
		setURL(url);
		setTSAAuthenticationType(tsaAuthenticationType);
		setCertificatePath(certificatePath);
		setCertificatePassword(certificatePassword);
	}
	
	
	/**
	 * @return the timeStampingType
	 */
	public TimeStampType getTimeStampingType() {
		return _timeStampType;
	}
	/**
	 * @param timeStampingType the timeStampingType to set
	 */
	public void setTimeStampingType(TimeStampType timeStampingType) {
		this._timeStampType = timeStampingType;
	}
	/**
	 * @return the tsaAuthenticationType
	 */
	public TSAAuthenticationType getTSAAuthenticationType() {
		return _tsaAuthenticationType;
	}
	/**
	 * @param tsaAuthenticationType the tsaAuthenticationType to set
	 */
	public void setTSAAuthenticationType(TSAAuthenticationType tsaAuthenticationType) {
		this._tsaAuthenticationType = tsaAuthenticationType;
	}
	/**
	 * @return the username
	 */
	public String getUsername() {
		return _username;
	}
	/**
	 * @param username the username to set
	 */
	public void setUsername(String username) {
		this._username = username;
	}
	/**
	 * @return the password
	 */
	public String getPassword() {
		return _password;
	}
	/**
	 * @param password the password to set
	 */
	public void setPassword(String password) {
		this._password = password;
	}
	/**
	 * @return the certificatePath
	 */
	public String getCertificatePath() {
		return _certificatePath;
	}
	/**
	 * @param certificatePath the certificatePath to set
	 */
	public void setCertificatePath(String certificatePath) {
		this._certificatePath = certificatePath;
	}
	/**
	 * @return the uRL
	 */
	public String getURL() {
		return _URL;
	}
	/**
	 * @param uRL the uRL to set
	 */
	public void setURL(String uRL) {
		_URL = uRL;
	}

	public char[] getCertificatePassword() {
		return certificatePassword;
	}

	public void setCertificatePassword(char[] certificatePassword) {
		this.certificatePassword = certificatePassword;
	}
	
	

}
