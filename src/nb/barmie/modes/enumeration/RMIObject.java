package nb.barmie.modes.enumeration;

import java.util.ArrayList;
import java.util.HashMap;
import nb.barmie.net.TCPEndpoint;

/***********************************************************
 * A container to manage and provide access to the details
 * of a single object that has been exposed through an RMI
 * registry service.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RMIObject {
	/*******************
	 * Properties
	 ******************/
	private final String _objectName;							//The name that the object is bound to in the RMI registry service
	private final HashMap<String, ArrayList<String>> _classes;	//The classes behind the object, mapped to any string annotations attached to the class definitions
	private TCPEndpoint _objectEndpoint;						//The host/port where the object is hosted
	private Exception _objectParsingException;					//Set if an exception occurred whilst parsing the object details from network packets
	
	/*******************
	 * Construct the object with the name that the remote object is bound to.
	 * 
	 * @param objectName The name that the remote object is bound to in an RMI registry.
	 ******************/
	public RMIObject(String objectName) {
		//Initialise the object
		this._objectName = objectName;
		this._classes = new HashMap<String, ArrayList<String>>();
		this._objectEndpoint = null;
		this._objectParsingException = null;
	}
	
	/*******************
	 * Add a class to the object description - this will be one of the
	 * hierarchy of classes and interfaces behind the object.
	 * 
	 * @param classname A fully-qualified class name extracted from the RMI ReplyData packet.
	 ******************/
	public void addClass(String classname) {
		this._classes.put(classname, new ArrayList<String>());
	}
	
	/*******************
	 * Add a string annotation to a class.
	 * 
	 * @param classname The fully-qualified class name to annotate.
	 * @param annotation The string annotation.
	 ******************/
	public void addStringAnnotation(String classname, String annotation) {
		this._classes.get(classname).add(annotation);
	}
	
	/*******************
	 * Get all string annotations from this object's classes.
	 * 
	 * @return A list of string annotations from this object's classes.
	 ******************/
	public ArrayList<String> getStringAnnotations() {
		ArrayList<String> annotations = new ArrayList<String>();
		
		//Build a list of string annotations for each class making up this object
		for(String className: this._classes.keySet()) {
			for(String annotation: this._classes.get(className)) {
				annotations.add(annotation);
			}
		}
		
		//Return the annotations
		return annotations;
	}
		
	/*******************
	 * Setters
	 ******************/
	public void setObjectEndpoint(TCPEndpoint endpoint) { this._objectEndpoint = endpoint; }
	public void setParsingException(Exception exception) { this._objectParsingException = exception; }
	
	/*******************
	 * Getters
	 ******************/
	public String getObjectName() { return this._objectName; }
	public HashMap<String, ArrayList<String>> getObjectClasses() { return this._classes; }
	public TCPEndpoint getObjectEndpoint() { return this._objectEndpoint; }
	public Exception getParsingException() { return this._objectParsingException; }
}
