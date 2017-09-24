package nb.barmie.modes.enumeration;

import java.net.InetAddress;
import java.rmi.AccessException;
import java.rmi.ConnectException;
import java.rmi.ConnectIOException;
import java.rmi.NoSuchObjectException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.ServerError;
import java.rmi.ServerException;
import java.rmi.ServerRuntimeException;
import java.rmi.UnknownHostException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import nb.barmie.net.TCPEndpoint;
import nb.barmie.net.TimeoutClientSocketFactory;
import nb.barmie.net.proxy.RMIReturnDataCapturingProxy;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * Class to perform enumeration of an RMI endpoint and
 * build a data structure describing it.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RMIEnumerator {
	/*******************
	 * Constants and properties
	 ******************/
	//Constants
	private final String DEFAULT_UNBIND_NAME = "7a7e92763ffa6ed3a01bc9308dec09a944a6c9ffe6475be7cf70b2ab660ea000d60db9dfe2acee3a59d162da82800bb6de2e5f515dc57b24dfbfa233973c43cb";
	
	//Program options (e.g. for TCP timeouts)
	private final ProgramOptions _options;
	
	/*******************
	 * Initialise the RMI enumerator with the given program options data.
	 * 
	 * @param options The program options.
	 ******************/
	public RMIEnumerator(ProgramOptions options) {
		this._options = options;
	}
	
	/*******************
	 * Enumerate a single RMI endpoint. This method probes the given endpoint
	 * to identify whether it's an RMI registry or object endpoint, then in the
	 * case of RMI registry endpoints a proxy is used to capture and extract
	 * additional details about the exposed objects.
	 * 
	 * @param target The TCP endpoint to enumerate.
	 * @return An RMIEndpoint object containing details of the endpoint.
	 *******************/
	public RMIEndpoint enumerateEndpoint(TCPEndpoint target) {
		RMIReturnDataCapturingProxy rmiProxy;
		RMIEndpoint rmie;
		RMIReplyDataParser replyParser;
		Registry reg;
		String[] objectNames;
		String unbindName;
		Object obj;
		int i;
		
		//Create an RMIEndpoint object for this target
		rmie = new RMIEndpoint(target);
		
		//Create a Registry reference to the endpoint
		try {
			reg = LocateRegistry.getRegistry(target.getHost(), target.getPort(), new TimeoutClientSocketFactory(this._options.getSocketTimeout()));
		} catch(RemoteException re) {
			//Could not create a reference to the registry
			throw new RuntimeException("Unable to create a java.rmi.Registry reference for the endpoint '" + target.getHost() + ":" + target.getPort() + "'.");
		}
		
		//Begin enumerating the endpoint
		try {
			//Attempt to retrieve a list of objects from the endpoint
			objectNames = reg.list();
			rmie.setIsRMIEndpoint(true);
			rmie.setIsRegistry(true);
			
			//Test whether the registry can be manipulated
			try {
				//Find an object name that isn't bound to the registry already
				unbindName = getUnboundObjectName(objectNames);
				
				//Attempt to unbind an object that isn't bound to the registry
				reg.unbind(unbindName);
			} catch(NotBoundException nbe) {
				//Looks like the registry can be manipulated remotely
				rmie.setIsRemotelyModifiable(true);
			} catch(Exception e) {
				//Registry cannot be manipulated remotely, swallow the exception
			}
			
			//Start a proxy to capture the object details
			rmiProxy = new RMIReturnDataCapturingProxy(InetAddress.getByName(target.getHost()), target.getPort(), this._options);
			rmiProxy.startProxy();
			
			//Get a new Registry reference pointing at the proxy
			reg = LocateRegistry.getRegistry(rmiProxy.getServerListenAddress().getHostAddress(), rmiProxy.getServerListenPort(), new TimeoutClientSocketFactory(this._options.getSocketTimeout()));
			
			//List objects to establish an RMI registry connection through the proxy
			objectNames = reg.list();
			
			//Create a ReplyData parser to extract object details from captured RMI ReplyData packets
			replyParser = new RMIReplyDataParser();
			
			//Request each of the exposed objects and extract information about the objects from the data captured by the proxy
			for(i = 0; i < objectNames.length; ++i) {
				//Reset the proxy data buffer
				rmiProxy.resetDataBuffer();
				
				//Request an object from the registry
				try {
					obj = reg.lookup(objectNames[i]);
				} catch(Exception e) {
					//Swallow the exception, we just need the data that came back through the proxy
				}
				
				//Delay to allow any remaining RMI ReplyData packets to be buffered from the above call to lookup()
				Thread.sleep(250);
				
				//If a new RMI connection was established then re-request this object
				if(rmiProxy.didReconnect() == true) {
					rmiProxy.resetReconnectFlag();
					--i;
				} else {
					//Extract object details from the data stream and store the details in the RMIEndpoint object
					rmie.addRMIObject(replyParser.extractObjectDetails(objectNames[i], rmiProxy.getDataBuffer()));
				}
			}
			
			//Done enumerating objects, shutdown the proxy
			rmiProxy.stopProxy(true);
		} catch(AccessException ae) {
			//Looks like an RMI registry endpoint but access is denied
			rmie.setIsRMIEndpoint(true);
			rmie.setIsRegistry(true);
			rmie.setEnumException(ae);
		} catch(NoSuchObjectException|ServerError|ServerException|ServerRuntimeException se) {
			//An RMI exception occurred on the endpoint indicating that it is an RMI endpoint but it's not clear whether it's an object or registry
			rmie.setIsRMIEndpoint(true);
			rmie.setEnumException(se);
		} catch(ConnectException|ConnectIOException|UnknownHostException ce) {
			//Unable to connect to the endpoint
			rmie.setEnumException(ce);
		} catch(Exception re) {
			//Other exceptions probably indicate that it isn't actually an RMI endpoint
			rmie.setEnumException(re);
		}
		
		//Return the RMI endpoint details
		return rmie;
	}
	
	/*******************
	 * Get an object name that isn't in the given list of bound object names.
	 * 
	 * Helper function to aid in testing whether a registry can be manipulated
	 * remotely.
	 * 
	 * @param objectNames The list of object names that are bound to the registry being tested.
	 * @return A string representing an object name that is not bound to the registry.
	 ******************/
	private String getUnboundObjectName(String[] objectNames) {
		SecureRandom sRand;
		ArrayList<String> objNames;
		String objName;
		
		//Start with defaults
		objNames = new ArrayList<String>(Arrays.asList(objectNames));
		objName = this.DEFAULT_UNBIND_NAME;
		sRand = new SecureRandom();
		
		//Loop until we find an object name that isn't bound in the registry
		while(objNames.contains(objName)) {
			//Generate a new random object name
			objName = Long.toHexString(sRand.nextLong()) + Long.toHexString(sRand.nextLong()) + Long.toHexString(sRand.nextLong());
		}
		
		//Return the object name to use
		return objName;
	}
}
