package nb.barmie.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import nb.barmie.exceptions.BaRMIeIllegalArgumentException;
import nb.barmie.exceptions.BaRMIeInvalidPortException;
import nb.barmie.net.TCPEndpoint;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/***********************************************************
 * Class to parse, load, validate and provide access to
 * command line options.
 **********************************************************
 * Command line should be one of the following:
 *	BaRMIe -enum [options] [target-host] [target-port]
 *	BaRMIe -attack [options] [target-host] [target-port]
 * 
 * Mode flags:
 * -enum		Enumerate the given target(s) to retrieve details of objects and exploits we can perform.
 * -attack		Enumerate the given target(s) and present attack options.
 * 
 * Options supported by all modes:
 * --targets	Used to specify a file containing targets (supports nmap output).
 * --timeout	Used to set timeout on blocking TCP operations.
 * 
 * Options supported by enumeration mode only:
 * --threads	Number of threads to use for scanning.
 **********************************************************
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ProgramOptions {
	/*******************
	 * Constants and properties
	 ******************/
	//Default option values
	private final String DEFAULT_MODE = "-enum";	//Default to enumeration mode if no mode is specified
	private final int DEFAULT_THREADS = 10;			//Default to using 10 worker threads
	private final int DEFAULT_SOCKTIMEOUT = 5000;	//Default to a 5 second timeout on blocking socket operations
	private final int DEFAULT_RMIPORT = 1099;		//Default TCP port for RMI registry services
	
	//Program option properties
	private String _mode;							//Execution mode - enum/attack
	private ArrayList<TCPEndpoint> _targets;		//Targets
	private int _threadCount;						//Number of threads to use
	private int _socketTimeout;						//Timeout for blocking socket operations
	
	/*******************
	 * Initialise default options and parse command line arguments.
	 * 
	 * @param args The strings passed to the program on the command line.
	 * @throws nb.barmie.exceptions.BaRMIeIllegalArgumentException If invalid parameters were passed to the program.
	 ******************/
	public ProgramOptions(String[] args) throws BaRMIeIllegalArgumentException, BaRMIeInvalidPortException {
		//Set default options
		this.setDefaultOptions();
		
		//Parse the command line arguments
		this.parseCommandLineArgs(args);
	}
	
	/*******************
	 * Initialise default program options.
	 ******************/
	private void setDefaultOptions() {
		this._mode = this.DEFAULT_MODE;
		this._targets = new ArrayList<TCPEndpoint>();
		this._threadCount = this.DEFAULT_THREADS;
		this._socketTimeout = this.DEFAULT_SOCKTIMEOUT;
	}
	
	/*******************
	 * Parse the command line arguments, validating along the way.
	 * 
	 * @param args The strings passed to the program on the command line.
	 ******************/
	private void parseCommandLineArgs(String[] args) throws BaRMIeIllegalArgumentException, BaRMIeInvalidPortException {
		LinkedList<String> argQueue = new LinkedList<String>(Arrays.asList(args));
		String targetHost;
		String opt;
		String val;
		int targetPort;
		
		//If the first parameter is "-enum" or "-attack" then set the mode
		if(argQueue.peekFirst().toLowerCase().equals("-enum") || argQueue.peekFirst().toLowerCase().equals("-attack")) {
			this._mode = argQueue.pop().toLowerCase();
		}
		
		//Handle options (all begin with '--')
		while(argQueue.size() > 0 && argQueue.peekFirst().startsWith("--")) {
			//Pop the option and value off of the argument queue
			opt = argQueue.pop().toLowerCase();
			val = argQueue.pop();
			
			//Handle the option
			switch(opt) {
				case "--threads":
					//Unsupported in attack mode
					if(this._mode.equals("-attack")) {
						throw new BaRMIeIllegalArgumentException("--threads option is not supported in attack mode.");
					}
					
					//Try to parse the value as an integer and store it
					try {
						this._threadCount = Integer.parseInt(val);
					} catch(NumberFormatException nfe) {
						throw new BaRMIeIllegalArgumentException("Thread count must be an integer.");
					}
					break;
					
				case "--timeout":
					//Try to parse the value as an integer and store it
					try {
						this._socketTimeout = Integer.parseInt(val);
					} catch(NumberFormatException nfe) {
						throw new BaRMIeIllegalArgumentException("Timeout must be an integer.");
					}
					break;
					
				case "--targets":
					//Try to parse the given file and build a list of targets
					this.loadTargets(val);
					break;
					
				default:
					//Unsupported option
					throw new BaRMIeIllegalArgumentException("Unsupported option specified (" + opt + ")");
			}
		}
		
		//Check remaining parameters (0 = targets should have been loaded from a file, 1 = target host specified, 3 = target host and port specified)
		if(argQueue.size() == 0) {
			//Make sure some targets were loaded...
			if(this._targets.size() == 0) {
				throw new BaRMIeIllegalArgumentException("No scan targets were specified.");
			}
		} else {
			//If targets were already loaded from a file then this may be a mistake (--targets and single target specified on command line)
			if(this._targets.size() > 0) {
				throw new BaRMIeIllegalArgumentException("Invalid command line, either specify a single target on the command line or load targets from a file using --targets.");
			}
			
			//We should only have 1 or 2 arguments remaining - target host or target host and port
			switch(argQueue.size()) {
				case 1:
					//Create a target from the given host and default RMI port
					this._targets.add(new TCPEndpoint(argQueue.pop(), DEFAULT_RMIPORT));
					break;
					
				case 2:
					//Grab the host and attempt to parse the port number
					opt = argQueue.pop();
					val = argQueue.pop();
					try {
						targetPort = Integer.parseInt(val);
					} catch(NumberFormatException nfe) {
						throw new BaRMIeIllegalArgumentException("Target port (" + val + ") must be a valid integer.");
					}
					
					//Create a target from the given host and port
					this._targets.add(new TCPEndpoint(opt, targetPort));
					break;
					
				default:
					//Invalid command line...
					throw new BaRMIeIllegalArgumentException("Invalid command line, parameters following the target are not supported.");
			}
		}
	}
	
	/*******************
	 * Load a targets file passed in on the command line.
	 * 
	 * @param targetFilename The filename passed in using the --targets command line parameter.
	 ******************/
	private void loadTargets(String targetFilename) throws BaRMIeIllegalArgumentException, BaRMIeInvalidPortException {
		//Work out the target file format and load targets from it accordingly
		switch(this.getNetworkTargetsFileFormat(targetFilename)) {
			case "basic":
				//Each line should contain a single host or space-separated host and port
				this.loadNetworkTargetsBasic(targetFilename);
				break;
				
			case "nmap":
				//Parse nmap output for open TCP port 1099, rmiregistry services, or Java RMI services
				this.loadNetworkTargetsNmap(targetFilename);
				break;
				
			case "gnmap":
				//Parse greppable nmap output for open TCP port 1099, rmiregistry services, or Java RMI services
				this.loadNetworkTargetsGnmap(targetFilename);
				break;
				
			case "nmapxml":
				//Parse nmap xml output for open TCP port 1099, rmiregistry services, or Java RMI services
				this.loadNetworkTargetsNmapXml(targetFilename);
				break;
		}
		
		//Throw an exception if no targets were loaded
		if(this._targets.size() == 0) {
			throw new BaRMIeIllegalArgumentException("No targets were identified within the given targets file.");
		}
	}
	
	/*******************
	 * Attempt to work out the format of a targets file (supports nmap output
	 * or target-per-line formatting).
	 * 
	 * @param targetFilename The filename passed in using the --targets command line parameter.
	 * @return The format of the targets file: basic, nmap, gnmap, or nmapxml.
	 ******************/
	private String getNetworkTargetsFileFormat(String targetFilename) throws BaRMIeIllegalArgumentException {
		BufferedReader targetFileReader = null;
		String fileLine;
		
		//Look for nmap or xml headers in the first two lines of the file in an attempt to determine the targets file format
		try {
			//Open the file and read the first line
			targetFileReader = new BufferedReader(new FileReader(targetFilename));
			fileLine = targetFileReader.readLine();
			
			//Check for an nmap or xml header
			if(fileLine.startsWith("# Nmap ")) {
				//Looks like nmap or greppable nmap output, read the next line to differentiate
				fileLine = targetFileReader.readLine();
				if(fileLine != null && fileLine.startsWith("Host: ")) {
					//Attempt to load the file as greppable nmap output
					return "gnmap";
				} else {
					//Attempt to load the file as normal nmap output
					return "nmap";
				}
			} else if(fileLine.startsWith("<?xml ")) {
				//Attempt to load the file as nmap xml output
				return "nmapxml";
			} else {
				//No nmap or xml header, attempt to load the file as target-per-line format
				return "basic";
			}
		} catch(FileNotFoundException fnfe) {
			//The targets file was not found
			throw new BaRMIeIllegalArgumentException("Targets file could not be found.", fnfe);
		} catch(IOException ioe) {
			//An exception occurred whilst reading from the file
			throw new BaRMIeIllegalArgumentException("Targets file could not be read.", ioe);
		} finally {
			//Close the file if it was opened
			if(targetFileReader != null) { try {targetFileReader.close(); } catch(IOException ioe) {} }
		}
	}
	
	/*******************
	 * Load network targets from a file containing a single host or
	 * space-separated host and port pair per line.
	 * 
	 * @param targetFilename The filename passed in using the --targets command line parameter.
	 ******************/
	private void loadNetworkTargetsBasic(String targetFilename) throws BaRMIeIllegalArgumentException, BaRMIeInvalidPortException {
		BufferedReader targetFileReader = null;
		String fileLine;
		String[] lineParts;
		
		//Load targets from the given file
		try {
			targetFileReader = new BufferedReader(new FileReader(targetFilename));
			while((fileLine = targetFileReader.readLine()) != null) {
				//Lines can either contain a host (with default RMI registry port), or a space-separated host and port
				lineParts = fileLine.split(" ");
				switch(lineParts.length) {
					case 1:
						//Add the target with the default RMI registry port
						this._targets.add(new TCPEndpoint(lineParts[0], this.DEFAULT_RMIPORT));
						break;
						
					case 2:
						//Add the target with the given host and port
						try {
							this._targets.add(new TCPEndpoint(lineParts[0], Integer.parseInt(lineParts[1])));
						} catch(NumberFormatException nfe) {
							//Invalid port number
							throw new BaRMIeIllegalArgumentException("Error parsing targets file, '" + lineParts[1] + "' is not a valid port number.");
						}
						break;
				}
			}
		} catch(FileNotFoundException fnfe) {
			//Targets file not found
			throw new BaRMIeIllegalArgumentException("Targets file could not be found.", fnfe);
		} catch(IOException ioe) {
			//Exception whilst reading from the file
			throw new BaRMIeIllegalArgumentException("Targets file could not be read.", ioe);
		} finally {
			//Close the file if it was opened
			if(targetFileReader != null) { try { targetFileReader.close(); } catch(IOException ioe) {} }
		}
	}
	
	/*******************
	 * Load network targets from standard nmap output.
	 * 
	 * @param targetFilename The filename passed in using the --targets command line parameter.
	 ******************/
	private void loadNetworkTargetsNmap(String targetFilename) throws BaRMIeIllegalArgumentException, BaRMIeInvalidPortException {
		BufferedReader targetFileReader = null;
		String fileLine;
		String currentHost = "";
		
		//Load targets from the given file
		try {
			targetFileReader = new BufferedReader(new FileReader(targetFilename));
			while((fileLine = targetFileReader.readLine()) != null) {
				//Check for the start of a host and record the host
				if(fileLine.startsWith("Nmap scan report for ")) {
					//Scan report line may contain a domain name followed by the IP address in brackets, retrieve the IP
					if(fileLine.contains("(")) {
						currentHost = fileLine.split(" ")[5];
						currentHost = currentHost.substring(1, currentHost.length() - 1);
					} else {
						currentHost = fileLine.split(" ")[4];
					}
				} else {
					//Check for interesting port scan results to target with BaRMIe
					if(fileLine.startsWith("1099/tcp") && fileLine.split("\\w+")[1].equals("open")) {
						//Found open TCP port 1099, track this target
						this._targets.add(new TCPEndpoint(currentHost, this.DEFAULT_RMIPORT));
					} else if(fileLine.contains("rmiregistry") || fileLine.contains("Java RMI") || fileLine.contains("java-rmi")) {
						//Found RMI registry service running on non-default port?
						try {
							this._targets.add(new TCPEndpoint(currentHost, Integer.parseInt(fileLine.split("/")[0])));
						} catch(NumberFormatException nfe) {
							//Invalid port number specified for 'rmiregistry' service
							throw new BaRMIeIllegalArgumentException("Error extracting targets from nmap output - the host '" + currentHost + "' appears to have an 'rmiregistry' service running on a non-standard port number that cannot e converted into an integer '" + fileLine.split("/")[0] + "'.");
						}
					}
				}
			}
		} catch(FileNotFoundException fnfe) {
			//Targets file not found
			throw new BaRMIeIllegalArgumentException("Targets file could not be found.", fnfe);
		} catch(IOException ioe) {
			//Exception whilst reading from the file
			throw new BaRMIeIllegalArgumentException("Targets file could not be read.", ioe);
		} finally {
			//Close the file if it was opened
			if(targetFileReader != null) { try { targetFileReader.close(); } catch(IOException ioe) {} }
		}
	}
	
	/*******************
	 * Load network targets from greppable nmap output.
	 * 
	 * @param targetFilename The filename passed in using the --targets command line parameter.
	 ******************/
	private void loadNetworkTargetsGnmap(String targetFilename) throws BaRMIeIllegalArgumentException, BaRMIeInvalidPortException {
		BufferedReader targetFileReader = null;
		String fileLine;
		String[] allScannedPorts;
		String[] portDetails;
		
		//Load targets from the given file
		try {
			targetFileReader = new BufferedReader(new FileReader(targetFilename));
			while((fileLine = targetFileReader.readLine()) != null) {
				//Check if the line is a port scan result line
				if(fileLine.startsWith("Host: ") && fileLine.contains("Ports: ")) {
					//Split the ports section of the line up
					allScannedPorts = fileLine.split("Ports: ")[1].split(", ");
					
					//Look for interesting port data strings
					for(String currentPortSection: allScannedPorts) {
						//Split the current port details up
						portDetails = currentPortSection.split("/");
						
						//Check for interesting port scan results to target with BaRMIe
						if(currentPortSection.startsWith("1099/open/tcp")) {
							//Found open TCP port 1099, track this target
							try { this._targets.add(new TCPEndpoint(fileLine.split(" ")[0], 1099)); } catch(BaRMIeInvalidPortException bipe) {}
						} else if(currentPortSection.contains("/open/") && (currentPortSection.contains("/rmiregistry/") || currentPortSection.contains("/java-rmi/") || currentPortSection.contains("/Java RMI/"))) {
							//Found RMI registry service on non-default port?
							try {
								this._targets.add(new TCPEndpoint(fileLine.split(" ")[0], Integer.parseInt(portDetails[0])));
							} catch(NumberFormatException nfe) {
								//Invalid port number specified for 'rmiregistry' service
								throw new BaRMIeIllegalArgumentException("Error extracting targets from nmap output - the host '" + fileLine.split(" ")[0] + "' appears to have an 'rmiregistry' service running on a non-standard port number that cannot e converted into an integer '" + portDetails[0] + "'.");
							}
						}
					}
				}
			}
		} catch(FileNotFoundException fnfe) {
			//Targets file not found
			throw new BaRMIeIllegalArgumentException("Targets file could not be found.", fnfe);
		} catch(IOException ioe) {
			//Exception whilst reading from the file
			throw new BaRMIeIllegalArgumentException("Targets file could not be read.", ioe);
		} finally {
			//Close the file if it was opened
			if(targetFileReader != null) { try { targetFileReader.close(); } catch(IOException ioe) {} }
		}
	}
	
	/*******************
	 * Load network targets from nmap xml output.
	 * 
	 * @param targetFilename The filename passed in using the --targets command line parameter.
	 ******************/
	private void loadNetworkTargetsNmapXml(String targetFilename) throws BaRMIeIllegalArgumentException, BaRMIeInvalidPortException {
		DocumentBuilderFactory dbf;
		DocumentBuilder db;
		Document xmlDoc;
		NodeList hostNodes;
		NodeList hostAddressNodes;
		NodeList portNodes;
		NodeList portServiceNodes;
		Element hostElement;
		Element portElement;
		int hostIndex;
		int portIndex;
		
		//Load targets from the given nmap xml file
		try {
			//Create an XML document builder factory and disable unnecessary features
			dbf = DocumentBuilderFactory.newInstance();
			dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
			dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
			dbf.setExpandEntityReferences(false);
			dbf.setXIncludeAware(false);
			
			//Create a document builder and load the XML document
			db = dbf.newDocumentBuilder();
			xmlDoc = db.parse(new File(targetFilename));
			
			//Iterate over host elements
			hostNodes = xmlDoc.getElementsByTagName("host");
			for(hostIndex = 0; hostIndex < hostNodes.getLength(); ++hostIndex) {
				//Get the current host element and address nodes
				hostElement = (Element)hostNodes.item(hostIndex);
				hostAddressNodes = hostElement.getElementsByTagName("address");
				
				//Get the child "port" nodes and Look for interesting open TCP ports
				portNodes = hostElement.getElementsByTagName("port");
				for(portIndex = 0; portIndex < portNodes.getLength(); ++portIndex) {
					//Get the current port element
					portElement = (Element)portNodes.item(portIndex);
					
					//Only handle TCP ports
					if(portElement.getAttribute("protocol").equalsIgnoreCase("tcp")) {
						//Only handle open TCP ports
						if(portElement.getElementsByTagName("state").getLength() == 1 && ((Element)portElement.getElementsByTagName("state").item(0)).getAttribute("state").equalsIgnoreCase("open")) {
							//If the port number is 1099 then add this target to the list
							if(portElement.getAttribute("portid").equals("1099")) {
								this._targets.add(new TCPEndpoint(((Element)hostAddressNodes.item(0)).getAttribute("addr"), 1099));
							} else {
								//If service detection was performed and the service is 'rmiregistry', or the product is listed as 'Java RMI', then add this target to the list
								if(portElement.getElementsByTagName("service").getLength() == 1) {
									if(((Element)portElement.getElementsByTagName("service").item(0)).getAttribute("name").equals("rmiregistry")) {
										try { this._targets.add(new TCPEndpoint(((Element)hostAddressNodes.item(0)).getAttribute("addr"), Integer.parseInt(portElement.getAttribute("portid")))); } catch(NumberFormatException ex) { throw new BaRMIeIllegalArgumentException("Invalid port number specified in nmap xml output ('" + portElement.getAttribute("portid") + ").", ex); }
									} else if(((Element)portElement.getElementsByTagName("service").item(0)).getAttribute("product").equals("Java RMI")) {
										try { this._targets.add(new TCPEndpoint(((Element)hostAddressNodes.item(0)).getAttribute("addr"), Integer.parseInt(portElement.getAttribute("portid")))); } catch(NumberFormatException ex) { throw new BaRMIeIllegalArgumentException("Invalid port number specified in nmap xml output ('" + portElement.getAttribute("portid") + ").", ex); }
									} else if(((Element)portElement.getElementsByTagName("service").item(0)).getAttribute("name").equals("java-rmi")) {
										try { this._targets.add(new TCPEndpoint(((Element)hostAddressNodes.item(0)).getAttribute("addr"), Integer.parseInt(portElement.getAttribute("portid")))); } catch(NumberFormatException ex) { throw new BaRMIeIllegalArgumentException("Invalid port number specified in nmap xml output ('" + portElement.getAttribute("portid") + ").", ex); }
									}
								}
							}
						}
					}
				}
			}
		} catch (ParserConfigurationException pce) {
			//Exception occurred whilst ocnfiguring the XML parser
			throw new RuntimeException("An exception occurred whilst configuring the XML parser.", pce);
		} catch (SAXException saxe) {
			//Exception occurred whilst processing the XML
			throw new BaRMIeIllegalArgumentException("An error occurred whilst attempting to parse the targets file as xml.", saxe);
		} catch (IOException ioe) {
			//Exception occurred whilst reading the file
			throw new BaRMIeIllegalArgumentException("Targets file could not be read.", ioe);
		}
	}
	
	/*******************
	 * Getters for program options.
	 ******************/
	public String getExecutionMode() { return this._mode; }
	public ArrayList<TCPEndpoint> getTargets() { return this._targets; }
	public int getThreadCount() { return this._threadCount; }
	public int getSocketTimeout() { return this._socketTimeout; }
}
