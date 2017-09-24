package nb.barmie.modes.enumeration;

import java.util.ArrayList;
import nb.barmie.net.TCPEndpoint;

/***********************************************************
 * A container to manage and provide access to the details
 * of a single RMI endpoint (RMI registry or object
 * endpoint).
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RMIEndpoint {
	/*******************
	 * Properties
	 ******************/
	private final TCPEndpoint _endpoint;				//The host and port of the RMI endpoint
	private boolean _isRMIEndpoint;						//True if this endpoint appears to be an RMI endpoint (RMI registry or RMI object endpoint)
	private boolean _isRegistry;						//True if this endpoint is an RMI registry, false if it's an RMI object endpoint
	private boolean _isRemotelyModifiable;				//True if the RMI registry appears to be remotely modifiable
	private final ArrayList<RMIObject> _exposedObjects;	//A list of all objects exposed by an RMI registry
	private Exception _enumerationException;			//Used to store any noteworthy exceptions triggered whilst enumerating the endpoint
	
	/*******************
	 * Initialise the RMI endpoint object with a given TCP endpoint.
	 * 
	 * @param endpoint The TCP endpoint this object represents.
	 ******************/
	public RMIEndpoint(TCPEndpoint endpoint) {
		this._endpoint = endpoint;
		this._isRMIEndpoint = false;
		this._isRegistry = false;
		this._isRemotelyModifiable = false;
		this._exposedObjects = new ArrayList<RMIObject>();
	}
	
	/*******************
	 * Add an RMIObject to the list of objects exposed through an RMI registry
	 * endpoint.
	 * 
	 * @param object An RMIObject describing the remote object.
	 ******************/
	public void addRMIObject(RMIObject object) {
		this._exposedObjects.add(object);
	}
	
	/*******************
	 * Check if any of the objects on this endpoint use a given class name.
	 * 
	 * @param className The class name to search for.
	 * @return True if any objects on this endpoint use the given class.
	 ******************/
	public boolean hasClass(String className) {
		for(RMIObject obj: this._exposedObjects) {
			for(String c: obj.getObjectClasses().keySet()) {
				if(c.equals(className)) {
					return true;
				}
			}
		}
		return false;
	}
	
	/*******************
	 * Find the name of an object that uses the given class.
	 * 
	 * Helper method to find objects to target.
	 * 
	 * @param className The class name to search for.
	 * @return An object name or null if no matching objects are found.
	 ******************/
	public String findObjectWithClass(String className) {
		for(RMIObject obj: this._exposedObjects) {
			for(String c: obj.getObjectClasses().keySet()) {
				if(c.equals(className)) {
					return obj.getObjectName();
				}
			}
		}
		return null;
	}
	
	/*******************
	 * Check if any of the objects on this endpoint are annotated with the
	 * given JAR file name.
	 * 
	 * @param jarName The jar file name to search for.
	 * @return True if any objects on this endpoint are annotated with the given jar file name.
	 ******************/
	public boolean hasJar(String jarName) {
		String[] pathParts;
		
		//Iterate over all annotations of all exposed objects
		for(RMIObject obj: this._exposedObjects) {
			for(String a: obj.getStringAnnotations()) {
				//Split the annotation on the space, colon, and semi-colon characters to get separate paths/URLs
				for(String path: a.split("[ ;:]")) {
					//Split the path on forward and backward slashes to get the JAR filename
					pathParts = path.split("[\\\\/]");
					
					//Check if the jar filename matches the one we were given
					if(pathParts.length > 0) {
						if(jarName.toLowerCase().equals(pathParts[pathParts.length - 1].toLowerCase())) {
							return true;
						}
					}
				}
			}
		}
		
		//No match
		return false;
	}
	
	/*******************
	 * Setters
	 ******************/
	public void setIsRMIEndpoint(boolean isRMIEndpoint) { this._isRMIEndpoint = isRMIEndpoint; }
	public void setIsRegistry(boolean isRegistry) { this._isRegistry = isRegistry; }
	public void setIsRemotelyModifiable(boolean isModifiable) { this._isRemotelyModifiable = isModifiable; }
	public void setEnumException(Exception ex) { this._enumerationException = ex; }
	
	/*******************
	 * Getters
	 ******************/
	public TCPEndpoint getEndpoint() { return this._endpoint; }
	public boolean isRMIEndpoint() { return this._isRMIEndpoint; }
	public boolean isRegistry() { return this._isRegistry && this._isRMIEndpoint; }
	public boolean isObjectEndpoint() { return (!this._isRegistry) && this._isRMIEndpoint; }
	public boolean isRemotelyModifiable() { return this._isRemotelyModifiable; }
	public Exception getEnumException() { return this._enumerationException; }
	public ArrayList<RMIObject> getExposedObjects() { return this._exposedObjects; }
}
