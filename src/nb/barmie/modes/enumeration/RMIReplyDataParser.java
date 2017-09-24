package nb.barmie.modes.enumeration;

import java.io.ObjectStreamConstants;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import nb.barmie.exceptions.BaRMIeInvalidPortException;
import nb.barmie.exceptions.BaRMIeInvalidReplyDataPacketException;
import nb.barmie.net.TCPEndpoint;

/***********************************************************
 * Parser for RMI ReplyData packets (Java serialisation).
 * 
 * Extracts class names, string annotations, and the TCP
 * endpoint details of a remote object from the RMI
 * ReplyData packet.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RMIReplyDataParser {
	/*******************
	 * Properties
	 ******************/
	private boolean _recordClasses;											//Indicates whether class names should be recorded during object parsing
	private LinkedList<HashMap<Byte, ArrayList<Character>>> _classDataDesc;	//List of classDescFlags mapped to field type codes from an object's classDesc
	
	/*******************
	 * Construct the reply data parser.
	 ******************/
	public RMIReplyDataParser() {
		this._recordClasses = true;
		this._classDataDesc = new LinkedList<HashMap<Byte, ArrayList<Character>>>();
	}
	
	/*******************
	 * Extract object details from a ReplyData that was captured through the
	 * RMI registry proxy.
	 * 
	 * @param objName The object name bound to the RMI registry for which data is being extracted.
	 * @param packetBytes The ReplyData captured from the RMI registry which contains the remote object description.
	 * @return An RMIObject describing the remote object.
	 ******************/
	public RMIObject extractObjectDetails(String objName, ArrayList<Byte> packetBytes) {
		LinkedList<Byte> dataStack;
		RMIObject obj;
		byte b;
		int i;
		
		//Create the RMIObject with the given object name
		obj = new RMIObject(objName);
		
		//Copy the given buffer into a stack for parsing
		dataStack = new LinkedList<Byte>();
		dataStack.addAll(packetBytes);
		
		//Set the 'recordClasses' flag to true so that class descriptions are added to the object description
		this._recordClasses = true;
		
		//Start parsing the object data
		try {
			//Validate the RMI packet type byte
			if(dataStack.peek() != 0x51) { throw new BaRMIeInvalidReplyDataPacketException("The data buffer begins with 0x" + String.format("%02x", dataStack.peek()) + ", which is not a ReplyData packet (0x51 expected)."); }
			dataStack.pop();
			
			//Validate the serialisation header
			if(dataStack.pop() != (byte)0xac || dataStack.pop() != (byte)0xed) { throw new BaRMIeInvalidReplyDataPacketException("The data buffer does not contain the serialisation magic number data."); }
			
			//Validate the serialisation stream version
			if(dataStack.pop() != 0x00 || dataStack.pop() != 0x05) { throw new BaRMIeInvalidReplyDataPacketException("The data buffer does not contain version 5 serialisation data."); }
			
			//Parse the serialisation stream elements to extract class names, annotations, and endpoint details
			while(dataStack.size() > 0) {
				//Get the type of the next stream element
				b = dataStack.pop();
				
				//Process the element accordingly
				switch(b) {
					//Skip over top-level block data elements
					case ObjectStreamConstants.TC_BLOCKDATA:
						//Read the block length
						b = dataStack.pop();
						
						//Skip over the block bytes
						for(i = 0; i < b; ++i) {
							dataStack.pop();
						}
						break;
						
					//Process the returned RMI object
					case ObjectStreamConstants.TC_OBJECT:
						this.handleNewObjectElement(obj, dataStack);
						break;
						
					//Unknown top-level stream element type
					default:
						throw new BaRMIeInvalidReplyDataPacketException("Unknown serialisation stream element (0x" + String.format("%02x", b) + ").");
				}
			}
		} catch(Exception e) {
			//Something went wrong, store the exception in the object element so it can be reviewed
			obj.setParsingException(e);
		}
		
		//Return the RMIObject
		return obj;
	}
	
	/*******************
	 * Handle a new object element in the ReplyData stream.
	 * 
	 * @param obj The RMIObject to populate with class names.
	 * @param dataStack The remaining data in the ReplyData packet.
	 ******************/
	private void handleNewObjectElement(RMIObject obj, LinkedList<Byte> dataStack) throws BaRMIeInvalidReplyDataPacketException {
		LinkedList<HashMap<Byte, ArrayList<Character>>> classDataDesc;
		HashMap<Byte, ArrayList<Character>> classDataDescElement;
		ArrayList<Character> classDataDescFields;
		
		//Reset the field data
		this._classDataDesc.clear();
		
		//Read the class desc
		this.handleClassDesc(obj, dataStack);
		
		//Set the 'recordClasses' flag to false so that no further classes are added to the object description
		this._recordClasses = false;
		
		//Create a fresh copy of the class data description to use in reading the object data
		classDataDesc = new LinkedList<HashMap<Byte, ArrayList<Character>>>();
		for(HashMap<Byte, ArrayList<Character>> el: this._classDataDesc) {
			classDataDescElement = new HashMap<Byte, ArrayList<Character>>();
			for(Byte key: el.keySet()) {
				classDataDescFields = new ArrayList<Character>();
				for(Character typeCode: el.get(key)) {
					classDataDescFields.add(typeCode);
				}
				classDataDescElement.put(key, classDataDescFields);
			}
			classDataDesc.add(classDataDescElement);
		}
		
		//Read in the class data based on the classDataDesc
		this.handleClassData(obj, dataStack, classDataDesc);
	}
	
	/*******************
	 * Handle a classDesc element.
	 * 
	 * @param obj The RMIObject to populate with class names.
	 * @param dataStack The remaining data in the ReplyData packet.
	 ******************/
	private void handleClassDesc(RMIObject obj, LinkedList<Byte> dataStack) throws BaRMIeInvalidReplyDataPacketException {
		String className;
		
		//Delegate depending on the type of classDesc
		switch(dataStack.pop()) {
			//ClassDesc
			case ObjectStreamConstants.TC_CLASSDESC:
				//Read the class name
				className = this.extractUtf8(dataStack);
				
				//Skip over the serialVersionUID
				this.extractLong(dataStack);
				
				//Handle the classDescInfo element, pass the class name in as there may be annotations for the class in there
				this.handleClassDescInfo(obj, dataStack, className);
				break;
				
			//ProxyClassDesc
			case ObjectStreamConstants.TC_PROXYCLASSDESC:
				//Handle the proxyClassDescInfo element
				this.handleProxyClassDescInfo(obj, dataStack);
				break;
				
			//Null - e.g. when the super class is null
			case ObjectStreamConstants.TC_NULL:
				break;
				
			//Unknown classDesc type
			default:
				throw new BaRMIeInvalidReplyDataPacketException("Unknown classDesc element type.");
		}
	}
	
	/*******************
	 * Handle a classDescInfo element and add the class name and any string
	 * annotations to the object description.
	 * 
	 * @param obj The RMIObject to populate with class names.
	 * @param dataStack The remaining data in the ReplyData packet.
	 * @param className The class name that was read prior to reading this classDescInfo element.
	 ******************/
	private void handleClassDescInfo(RMIObject obj, LinkedList<Byte> dataStack, String className) throws BaRMIeInvalidReplyDataPacketException {
		ArrayList<String> stringAnnotations;
		byte classDescFlags;
		int i;
		
		//Read the class desc flags
		classDescFlags = dataStack.pop();
		
		//Read the field data
		this.handleFields(obj, dataStack, classDescFlags);
		
		//Read the class annotations
		stringAnnotations = this.handleClassAnnotation(obj, dataStack);
		
		//Add the class to the object description along with any string annotations
		if(this._recordClasses) {
			obj.addClass(className);
			for(String annotation: stringAnnotations) {
				obj.addStringAnnotation(className, annotation);
			}
		}
		
		//Read the super class description
		this.handleClassDesc(obj, dataStack);
	}
	
	/*******************
	 * Handle a proxyClassDescInfo element and add the interface names and
	 * string annotations to the object description.
	 * 
	 * @param obj The RMIObject to populate with class names.
	 * @param dataStack The remaining data in the ReplyData packet.
	 ******************/
	private void handleProxyClassDescInfo(RMIObject obj, LinkedList<Byte> dataStack) throws BaRMIeInvalidReplyDataPacketException {
		String[] interfaceNames;
		ArrayList<String> stringAnnotations;
		int interfaceCount;
		int i;
		
		//Read the number of interfaces from the packet
		interfaceCount = this.extractInt(dataStack);
		
		//Read in the interface names
		interfaceNames = new String[interfaceCount];
		for(i = 0; i < interfaceCount; ++i) {
			interfaceNames[i] = this.extractUtf8(dataStack);
		}
		
		//Handle class annotations and retrieve any string annotations to add to the object description
		stringAnnotations = this.handleClassAnnotation(obj, dataStack);
		
		//Add the interfaces to the object description
		if(this._recordClasses) {
			for(i = 0; i < interfaceCount; ++i) {
				//Add the interface name
				obj.addClass(interfaceNames[i]);
				
				//Attach any related string annotations to the first interface
				if(i == 0) {
					for(String annotation: stringAnnotations) {
						obj.addStringAnnotation(interfaceNames[i], annotation);
					}
				}
			}
		}
		
		//Read the super class description
		this.handleClassDesc(obj, dataStack);
	}
	
	/*******************
	 * Handle a classAnnotation element and return any string annotation
	 * elements in the classAnnotation.
	 * 
	 * @param obj The RMIObject to populate with class names.
	 * @param dataStack The remaining data in the ReplyData packet.
	 * @return An ArrayList of strings representing any string annotations extracted from the stream.
	 ******************/
	private ArrayList<String> handleClassAnnotation(RMIObject obj, LinkedList<Byte> dataStack) throws BaRMIeInvalidReplyDataPacketException {
		ArrayList<String> stringAnnotations;
		byte b;
		
		//Create the arraylist
		stringAnnotations = new ArrayList<String>();
		
		//Read elements from the stream until a TC_ENDBLOCKDATA element is read
		while((b = dataStack.pop()) != ObjectStreamConstants.TC_ENDBLOCKDATA) {
			//Handle the annotation
			switch(b) {
				//Read string annotations into an array list to return
				case ObjectStreamConstants.TC_STRING:
					stringAnnotations.add(this.extractUtf8(dataStack));
					break;
					
				//Skip over reference annotations
				case ObjectStreamConstants.TC_REFERENCE:
					//Read past the reference handle
					this.extractInt(dataStack);
					break;
					
				//Ignore null annotations...
				case ObjectStreamConstants.TC_NULL:
					break;
					
				//Unknown annotation type
				default:
					throw new BaRMIeInvalidReplyDataPacketException("Unknown classAnnotation element type (0x" + String.format("%02x", b) + ").");
			}
		}
		
		//Return the string annotations
		return stringAnnotations;
	}
	
	/*******************
	 * Handle field descriptions.
	 * 
	 * @param obj The RMIObject to populate with class names.
	 * @param dataStack The remaining data in the ReplyData packet.
	 ******************/
	private void handleFields(RMIObject obj, LinkedList<Byte> dataStack, byte classDescFlags) throws BaRMIeInvalidReplyDataPacketException {
		ArrayList<Character> fieldTypeCodes;
		HashMap<Byte, ArrayList<Character>> classDataDesc;
		char typeCode;
		int fieldCount;
		int i;
		
		//Create an array list of field type codes
		fieldTypeCodes = new ArrayList<Character>();
		
		//Read the number of fields
		fieldCount = this.extractShort(dataStack);
		
		//Read the field descriptions
		for(i = 0; i < fieldCount; ++i) {
			//Read the field type code
			typeCode = (char)dataStack.pop().byteValue();
			
			//Add it to the list
			fieldTypeCodes.add(typeCode);
			
			//Read the field data
			switch(typeCode) {
				//Handle primitive types by reading the field name
				case 'B':
				case 'C':
				case 'D':
				case 'F':
				case 'I':
				case 'J':
				case 'S':
				case 'Z':
					//Skip over the field name
					this.extractUtf8(dataStack);
					break;
					
				//Handle object and array types by reading the field name and class name
				case '[':
				case 'L':
					//Skip over the field name
					this.extractUtf8(dataStack);
					
					//Skip over the class name
					this.handleStringElement(dataStack);
					break;
					
				//Invalid field type
				default:
					throw new BaRMIeInvalidReplyDataPacketException("Invalid field type code (0x" + String.format("%02x", (byte)typeCode) + ").");
			}
		}
		
		//Add the field data to the class data description
		classDataDesc = new HashMap<Byte, ArrayList<Character>>();
		classDataDesc.put(classDescFlags, fieldTypeCodes);
		this._classDataDesc.push(classDataDesc);
	}
	
	/*******************
	 * Handle a string element.
	 * 
	 * @param obj The RMIObject to populate with class names.
	 ******************/
	private void handleStringElement(LinkedList<Byte> dataStack) throws BaRMIeInvalidReplyDataPacketException {
		//Handle a string based on the type
		switch(dataStack.pop()) {
			//Standard string
			case ObjectStreamConstants.TC_STRING:
				this.extractUtf8(dataStack);
				break;
				
			//Long string
			case ObjectStreamConstants.TC_LONGSTRING:
				this.extractLongUtf8(dataStack);
				break;
				
			//References
			case ObjectStreamConstants.TC_REFERENCE:
				this.extractInt(dataStack);
				break;
				
			//Invalid string type
			default:
				throw new BaRMIeInvalidReplyDataPacketException("Invalid string element type.");
		}
	}
	
	/*******************
	 * Handle class data including extraction of the TC_BLOCKDATA element that
	 * contains the endpoint for the remote object.
	 * 
	 * @param obj The RMIObject to populate with class names.
	 * @param dataStack The remaining data in the ReplyData packet.
	 * @param classDataDesc A data structure defining the structure of the class data in the stream.
	 ******************/
	private void handleClassData(RMIObject obj, LinkedList<Byte> dataStack, LinkedList<HashMap<Byte, ArrayList<Character>>> classDataDesc) throws BaRMIeInvalidReplyDataPacketException {
		HashMap<Byte, ArrayList<Character>> desc;
		ArrayList<Character> fieldTypes;
		byte classDescFlags;
		byte objType;
		
		//Loop over the class data description elements
		while(classDataDesc.size() > 0) {
			//Pop a class data description off the stack (the data of the most-super class is written out first)
			desc = classDataDesc.pop();
			
			//Get the flags and field types
			classDescFlags = (byte)desc.keySet().toArray()[0];
			fieldTypes = desc.get(classDescFlags);
			
			//Read the class data based on the flags
			if((classDescFlags & ObjectStreamConstants.SC_SERIALIZABLE) == ObjectStreamConstants.SC_SERIALIZABLE) {
				//Read/skip over the field values based on type
				for(Character typeCode: fieldTypes) {
					switch(typeCode) {
						//Pop eight-byte values off the stack (pop four bytes, then fall through to pop remaining four bytes)
						case 'J':	//Long
						case 'D':	//Double
							dataStack.pop();
							dataStack.pop();
							dataStack.pop();
							dataStack.pop();
							
						//Pop four-byte values off
						case 'I':	//Integer
						case 'F':	//Float
							dataStack.pop();
							dataStack.pop();
							
						//Pop two-byte values off
						case 'S':	//Short
							dataStack.pop();
							
						//Pop one-byte values off the data stack
						case 'B':	//Byte
						case 'C':	//Char
						case 'Z':	//Boolean
							dataStack.pop();
							break;
							
						//Handle objects
						case 'L':
							//Work out the object type
							objType = dataStack.pop();
							switch(objType) {
								//Recurse back into handleNewObjectElement() to handle object elements
								case ObjectStreamConstants.TC_OBJECT:
									this.handleNewObjectElement(obj, dataStack);
									break;
									
								//Handle strings
								case ObjectStreamConstants.TC_STRING:
									this.extractUtf8(dataStack);
									break;
									
								//Handle references
								case ObjectStreamConstants.TC_REFERENCE:
									this.extractInt(dataStack);
									break;
									
								//Handle NULL objects
								case ObjectStreamConstants.TC_NULL:
									break;
									
								//Unknown object type
								default:
									throw new BaRMIeInvalidReplyDataPacketException("Unexpected byte when handling an object field value.");
							}
							break;
							
						//Handle arrays
						case '[':
							//Or not, for now...
							throw new BaRMIeInvalidReplyDataPacketException("Invalid field type code ([).");
							
						//Invalid type code
						default:
							throw new BaRMIeInvalidReplyDataPacketException("Invalid field type code (" + typeCode + ").");
					}
				}
				
				//Read object annotations if necessary and extract the object endpoint if identified
				if((classDescFlags & ObjectStreamConstants.SC_WRITE_METHOD) == ObjectStreamConstants.SC_WRITE_METHOD) {
					this.handleObjectAnnotation(obj, dataStack);
				}
			} else if((classDescFlags & ObjectStreamConstants.SC_EXTERNALIZABLE) == ObjectStreamConstants.SC_EXTERNALIZABLE) {
				if((classDescFlags & ObjectStreamConstants.SC_BLOCK_DATA) == ObjectStreamConstants.SC_BLOCK_DATA) {
					//Read object annotations...
					throw new BaRMIeInvalidReplyDataPacketException("Class data loading with SC_EXTERNALIZABLE and SC_BLOCK_DATA not implemented yet...");
				} else {
					//Read external contents
					// - NB: this is class-specific and requires knowledge of the underlying class(es) to parse
					throw new BaRMIeInvalidReplyDataPacketException("Class data loading with SC_EXTERNALIZABLE and !SC_BLOCK_DATA is class-specific and not available...");
				}
			}
		}
	}
	
	/*******************
	 * Handle an objectAnnotation element, extracting the object endpoint
	 * details if found.
	 * 
	 * @param obj The RMIObject to populate with class names.
	 * @param dataStack The remaining data in the ReplyData packet.
	 ******************/
	private void handleObjectAnnotation(RMIObject obj, LinkedList<Byte> dataStack) throws BaRMIeInvalidReplyDataPacketException {
		byte b;
		
		//Read elements from the stream until a TC_ENDBLOCKDATA element is read
		while((b = dataStack.pop()) != ObjectStreamConstants.TC_ENDBLOCKDATA) {
			//Handle the annotation
			switch(b) {
				//Look for object endpoint details in block data elements
				case ObjectStreamConstants.TC_BLOCKDATA:
					//Push the block type back on to the stack and extract endpoint details if found
					dataStack.push(ObjectStreamConstants.TC_BLOCKDATA);
					this.extractObjectEndpointFromBlockData(obj, dataStack);
					break;
					
				//Skip over object annotations
				case ObjectStreamConstants.TC_OBJECT:
					this.handleNewObjectElement(obj, dataStack);
					break;
					
				//Ignore null annotations...
				case ObjectStreamConstants.TC_NULL:
					break;
					
				//Unknown annotation type
				default:
					throw new BaRMIeInvalidReplyDataPacketException("Unknown classAnnotation element type (0x" + String.format("%02x", b) + ").");
			}
		}
	}
	
	/*******************
	 * Handle a block data element found within an object annotation.
	 * 
	 * This block of data may contain the host and port where a remote object
	 * can be accessed.
	 * 
	 * @param obj The RMIObject to populate with class names.
	 * @param dataStack The remaining data in the ReplyData packet.
	 ******************/
	private void extractObjectEndpointFromBlockData(RMIObject obj, LinkedList<Byte> dataStack) throws BaRMIeInvalidReplyDataPacketException {
		LinkedList<Byte> blockData;
		int blockSize;
		int i;
		
		//Read the block data from the stack
		blockData = new LinkedList<Byte>();
		switch(dataStack.pop()) {
			//Handle TC_BLOCKDATA elements
			case ObjectStreamConstants.TC_BLOCKDATA:
				//Read the block size and contents
				blockSize = Byte.toUnsignedInt(dataStack.pop());
				for(i = 0; i < blockSize; ++i) {
					blockData.add(dataStack.pop());
				}
				break;
				
			//Unknown block data type
			default:
				throw new BaRMIeInvalidReplyDataPacketException("Invalid block data element type in class annotation.");
		}
		
		//Examine the block data for object endpoint details (note peeking at the block data, not the data stack)
		if(this.peekShort(blockData) == 10) {
			//The first two bytes are 0x00 0a, check for the string "UnicastRef"
			if(this.extractUtf8(blockData).equals("UnicastRef")) {
				//UnicastRef found in the block data, extract the object's host and port and add them to the object description (note extraction from block data, not data stack)
				try {
					obj.setObjectEndpoint(new TCPEndpoint(this.extractUtf8(blockData), this.extractInt(blockData)));
				} catch(BaRMIeInvalidPortException bipe) {
					throw new BaRMIeInvalidReplyDataPacketException("UnicastRef contained an invalid port number.", bipe);
				}
			}
		} else if(this.peekShort(blockData) == 11) {
			//The first two bytes are 0x00 0b, check for the string "UnicastRef2"
			if(this.extractUtf8(blockData).equals("UnicastRef2")) {
				//UnicastRef2 found in the block data, extract the object's host and port and add them to the object description
				try {
					//Skip over a byte
					blockData.pop();
					
					//Extract the host name and port
					obj.setObjectEndpoint(new TCPEndpoint(this.extractUtf8(blockData), this.extractInt(blockData)));
				} catch(BaRMIeInvalidPortException bipe) {
					throw new BaRMIeInvalidReplyDataPacketException("UnicastRef contained an invalid port number.", bipe);
				}
			}
		}
	}
	
	/*******************
	 * Read a short from the data stack.
	 * 
	 * @param dataStack The remaining data from the RMI ReplyData packet.
	 * @return The short extracted from the serialisation data.
	 ******************/
	private short extractShort(LinkedList<Byte> dataStack) {
		//Read two bytes from the stack and bit-shift/mask them into a short
		return (short)(
				((dataStack.pop() << 8) & 0xff00) +
				( dataStack.pop()       &   0xff)
		);
	}
	
	/*******************
	 * Return a short from the data stack without popping the short off the
	 * stack.
	 * 
	 * @param dataStack The remaining data from the RMI ReplyData packet.
	 * @return The short extracted from the serialisation data.
	 ******************/
	private short peekShort(LinkedList<Byte> dataStack) {
		//Peek at the next two bytes from the stack and bit-shift/mask them into a short
		return (short)(
				((dataStack.get(0) << 8) & 0xff00) +
				( dataStack.get(1)       &   0xff)
		);
	}
	
	/*******************
	 * Read an int from the data stack.
	 * 
	 * @param dataStack The remaining data from the RMI ReplyData packet.
	 * @return The int extracted from the serialisation data.
	 ******************/
	private int extractInt(LinkedList<Byte> dataStack) {
		//Read four bytes from the stack and bit-shift/mask them into an int
		return (int)(
				((dataStack.pop() << 24) & 0xff000000) +
				((dataStack.pop() << 16) &   0xff0000) +
				((dataStack.pop() <<  8) &     0xff00) +
				( dataStack.pop()        &       0xff)
		);
	}
	
	/*******************
	 * Read a long from the data stack.
	 * 
	 * @param dataStack The remaining data from the RMI ReplyData packet.
	 * @return The long extracted from the serialisation data.
	 ******************/
	private long extractLong(LinkedList<Byte> dataStack) {
		//Read eight bytes from the stack and bit-shift/mask them into a long
		return (long)(
				((dataStack.pop() << 56) & 0xff00000000000000L) +
				((dataStack.pop() << 48) &   0xff000000000000L) +
				((dataStack.pop() << 40) &     0xff0000000000L) +
				((dataStack.pop() << 32) &       0xff00000000L) +
				((dataStack.pop() << 24) &         0xff000000 ) +
				((dataStack.pop() << 16) &           0xff0000 ) +
				((dataStack.pop() <<  8) &             0xff00 ) +
				( dataStack.pop()        &               0xff )
		);
	}
	
	/*******************
	 * Read a UTF8 string from the data stack.
	 * 
	 * @param dataStack The remaining data from the RMI ReplyData packet.
	 * @return The string extracted from the serialisation data.
	 ******************/
	private String extractUtf8(LinkedList<Byte> dataStack) {
		StringBuilder builder;
		int stringLength;
		int i;
		
		//Read the string length from the stack
		stringLength = Short.toUnsignedInt(this.extractShort(dataStack));
		
		//Read the string from the data stack
		builder = new StringBuilder();
		for(i = 0; i < stringLength; ++i) {
			builder.append((char)dataStack.pop().byteValue());
		}
		
		//Return the result
		return builder.toString();
	}
	
	/*******************
	 * Read a long UTF8 string from the data stack.
	 * 
	 * @param dataStack The remaining data from the RMI ReplyData packet.
	 * @return The string extracted from the serialisation data.
	 ******************/
	private String extractLongUtf8(LinkedList<Byte> dataStack) {
		StringBuilder builder;
		long stringLength;
		int i;
		
		//Read the string length from the stack
		stringLength = this.extractLong(dataStack);
		
		//Read the string from the data stack
		builder = new StringBuilder();
		for(i = 0; i < stringLength; ++i) {
			builder.append((char)dataStack.pop().byteValue());
		}
		
		//Return the result
		return builder.toString();
	}
}
