package controller;

import sign.DigestAlgorithm;
import sign.XAdESSigner;
import timestamp.TSAAuthenticationType;
import timestamp.TimeStamp;
import timestamp.TimeStampType;

import java.util.Scanner;

import io.ParameterController;
import pkcs.*;

public class Runnable {
	public static void main(String[] args) throws Exception {
		runWithExternalInput(args);
	}
	
	/**
	 * Run library with external parameter
	 * @param args
	 */
	public static void runWithExternalInput(String[] args) {
		try {
			ParameterController paramCtrl = new ParameterController(args);
			
			// Input-Output
			String signType = paramCtrl.getParameterValue("-signType");
		    String inputFile = paramCtrl.getParameterValue("-inputFile");
			String outputFile = paramCtrl.getParameterValue("-outputFile");
			String inputFolder = paramCtrl.getParameterValue("-inputFolder");
			String outputFolder = paramCtrl.getParameterValue("-outputFolder");
			String outputSuffix = paramCtrl.getParameterValue("-outputSuffix");
			
			//PKCS12 Parameter
			String pkcs12FilePath = paramCtrl.getParameterValue("-pkcs12FilePath");
			String pkcs12Password = paramCtrl.getParameterValue("-pkcs12Password");
			
			//PKCS11 Parameter
			String pkcs11TokenName = paramCtrl.getParameterValue("-pkcs11TokenName");
			String pkcs11LibraryPath = paramCtrl.getParameterValue("-pkcs11LibraryPath");
			String pkcs11TokenPin = paramCtrl.getParameterValue("-pkcs11Pin");
			String pkcs11KeyStorePassword = paramCtrl.getParameterValue("-pkcs11KeyStorePassword");
			String pkcs11SearchKeyword = paramCtrl.getParameterValue("-pkcs11SeachKeyword");
			
			//TimeStamp URL
			TimeStampType timeStampType = paramCtrl.getParameterValue("-timeStampType") != null ? TimeStampType.valueOf(paramCtrl.getParameterValue("-timeStampType")) : null;
			TSAAuthenticationType tsaAuthenticationType = paramCtrl.getParameterValue("-tsaAuthenticationType") != null ? TSAAuthenticationType.valueOf(paramCtrl.getParameterValue("-tsaAuthenticationType")) : null;
			String tsaURL = paramCtrl.getParameterValue("-tsaURL");
			String tsaUsername = paramCtrl.getParameterValue("-tsaUsername");
			String tsaPassword = paramCtrl.getParameterValue("-tsaPassword");
			String tsaPKCS12File = paramCtrl.getParameterValue("-tsaPKCS12File");
			String tsaPKCS12Password = paramCtrl.getParameterValue("-tsaPKCS12Password");
			TimeStamp timeStamp;
			switch (timeStampType) {
				case COMPUTER_CLOCK:
					timeStamp = new TimeStamp(timeStampType);
					break;
				case TSA:
					switch (tsaAuthenticationType) {
					case NO_AUTHENTICATION:
						timeStamp = new TimeStamp(timeStampType, tsaURL, tsaAuthenticationType);
						break;
					case USERNAME_PASSWORD:
						timeStamp = new TimeStamp(timeStampType, tsaURL, tsaAuthenticationType, tsaUsername, tsaPassword);
						break;
					case CERTIFICATE:
						timeStamp = new TimeStamp(timeStampType, tsaURL, tsaAuthenticationType, tsaPKCS12File, tsaPKCS12Password.toCharArray());
						break;
					default:
						throw new Exception("TSA authentication must be input");
					}
					break;
				default:
					timeStamp = new TimeStamp(TimeStampType.COMPUTER_CLOCK);
			}
			
			//Other sign parameter
			DigestAlgorithm digestAlgorithm = paramCtrl.getParameterValue("-digestAlgorithm") != null ? DigestAlgorithm.valueOf(paramCtrl.getParameterValue("-digestAlgorithm")) : null;
			String signLevel = paramCtrl.getParameterValue("-signLevel");
			
			//PKCS
			PKCS12Instance pkcs12 = null;
			PKCS11Instance pkcs11 = null;
			
			if (pkcs12FilePath != null && pkcs12Password != null) {
				pkcs12 = new PKCS12Instance(pkcs12FilePath, pkcs12Password);
			} else if (pkcs11TokenName != null && pkcs11LibraryPath != null && pkcs11TokenPin != null && pkcs11KeyStorePassword != null && pkcs11SearchKeyword != null) {
				pkcs11 = new PKCS11Instance(pkcs11TokenName, pkcs11LibraryPath, pkcs11TokenPin, pkcs11KeyStorePassword, pkcs11SearchKeyword);
			} else {
				throw new Exception("Incomplete certificate input");
			}
			
			//Let's sign
			if (signType.equalsIgnoreCase("single")) {
				if (pkcs12 != null) {
					if (signLevel.equalsIgnoreCase("BES")) {
						new XAdESSigner().signBESOnce(inputFile, outputFile, pkcs12, digestAlgorithm);
					} else if (signLevel.equalsIgnoreCase("T")) {
						new XAdESSigner().signTOnce(inputFile, outputFile, pkcs12, digestAlgorithm, timeStamp);
					} else {
						throw new Exception("Support at 'BES' and 'T' level");
					}
				} else if ((pkcs11 != null)) {
					if (signLevel.equalsIgnoreCase("BES")) {
						new XAdESSigner().signBESOnce(inputFile, outputFile, pkcs11, digestAlgorithm);
					} else if (signLevel.equalsIgnoreCase("T")) {
						new XAdESSigner().signTOnce(inputFile, outputFile, pkcs11, digestAlgorithm, timeStamp);
					} else {
						throw new Exception("Support at 'BES' and 'T' level");
					}
				}
			}
			else if (signType.equalsIgnoreCase("multiple")) {
				if (pkcs12 != null) {
					if (signLevel.equalsIgnoreCase("BES")) {
						new XAdESSigner().signBESMultiple(inputFolder, outputFolder, outputSuffix, pkcs12, digestAlgorithm);
					} else if (signLevel.equalsIgnoreCase("T")) {
						new XAdESSigner().signTMultiple(inputFolder, outputFolder, outputSuffix, pkcs12, digestAlgorithm, timeStamp);
					} else {
						throw new Exception("Support at 'BES' and 'T' level");
					}
				} else if ((pkcs11 != null)) {
					if (signLevel.equalsIgnoreCase("BES")) {
						new XAdESSigner().signBESMultiple(inputFolder, outputFolder, outputSuffix, pkcs11, digestAlgorithm);
					} else if (signLevel.equalsIgnoreCase("T")) {
						new XAdESSigner().signTMultiple(inputFolder, outputFolder, outputSuffix, pkcs11, digestAlgorithm, timeStamp);
					} else {
						throw new Exception("Support at 'BES' and 'T' level");
					}
				}
			} else {
				throw new Exception("Sign type must be 'single' or 'multiple only'");
			}
			
			System.out.println("Complete");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			System.out.println("Press enter to exit");
			(new Scanner(System.in)).nextLine();
		}
	}
}
