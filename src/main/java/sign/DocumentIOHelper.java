package sign;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class DocumentIOHelper {
	
	public static Document getXMLDocumentByPath(String path) throws ParserConfigurationException, SAXException, IOException {
		File xmlFile = new File(path);
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder dBuilder = factory.newDocumentBuilder();
		return dBuilder.parse(xmlFile);
	}
	
	public static void writeSignedFile(Document doc, String path) throws FileNotFoundException {
		FileOutputStream output = new FileOutputStream(path);
		XMLUtils.outputDOM(doc, output);
	}
	
}
