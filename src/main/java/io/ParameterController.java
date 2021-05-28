package io;

import java.util.HashMap;
import java.util.Arrays;
import java.util.List;
import java.nio.charset.Charset;

public class ParameterController {
	
	private List<String> parameterList;
	private HashMap<String, String> libraryParameter;
    private Charset UTF_8 = Charset.forName("UTF-8");
	
	
	public ParameterController(String[] args) throws Exception {
		System.out.println("Intializing library parameter...");
		libraryParameter = new HashMap<String, String>();
		parameterList = Arrays.asList(new String[] {  });
		generateParameter(args);
	}
	
	private void generateParameter(String[] args) throws Exception {
		if (!validateRequireSchema(args)) {
			throw new Exception("Required parameter is missing");
		}
		
		if (args.length == 0) {
			throw new Exception("Parameter cannot be blank");
		}
		
		System.out.println("\tParameter list:");
		for(int i=0; i<args.length; i+=2) {
			if (args[i].startsWith("-")) {
				System.out.println("\t\t" + args[i].toString().trim() + ": " + args[i+1].toString().trim());
				String value = new String((args[i+1]).getBytes(), UTF_8);
				libraryParameter.put(args[i], value);
			} else {
				throw new Exception("Unrecognized paramater type");
			}
		}
		
	}
	
	private boolean validateRequireSchema(String[] args) {
		System.out.println("\tValidating required parameter...");
		
		List<String> argsList = Arrays.asList(args);
		
		if (argsList.containsAll(parameterList)) {
			System.out.println("\tRequired parameter complete.");
			return true;
		}
		else
		{
			System.out.println("\tRequired parameter incomplete.");
			return false;
		}
	}
	
	/**
	 * Get library parameter from external input
	 * @param key Parameter key name
	 * @return
	 */
	public String getParameterValue(String key) {
		return libraryParameter.get(key);
	}


}
