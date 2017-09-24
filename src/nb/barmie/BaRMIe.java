package nb.barmie;

import nb.barmie.exceptions.BaRMIeIllegalArgumentException;
import nb.barmie.exceptions.BaRMIeInvalidPortException;
import nb.barmie.modes.attack.AttackMode;
import nb.barmie.modes.enumeration.EnumerationMode;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * Java RMI enumeration and attack tool.
 **********************************************************
 * v1.0
 *  -> Initial release with several attacks and
 *     deserialization payloads.
 **********************************************************
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIe {
	/*******************
	 * Entry point - parse command line params, validate, and run the selected
	 * mode.
	 ******************/
	public static void main(String[] args) {
		ProgramOptions options;
		
		//Print a banner 'cause leet and stuff.
		System.out.println("\n  ▄▄▄▄    ▄▄▄       ██▀███   ███▄ ▄███▓ ██▓▓█████ \n" +
						   " ▓█████▄ ▒████▄    ▓██ ▒ ██▒▓██▒▀█▀ ██▒▓██▒▓█   ▀ \n" +
						   " ▒██▒ ▄██▒██  ▀█▄  ▓██ ░▄█ ▒▓██    ▓██░▒██▒▒███   \n" +
						   " ▒██░█▀  ░██▄▄▄▄██ ▒██▀▀█▄  ▒██    ▒██ ░██░▒▓█  ▄ \n" +
						   " ░▓█  ▀█▓ ▓█   ▓██▒░██▓ ▒██▒▒██▒   ░██▒░██░░▒████▒\n" +
						   " ░▒▓███▀▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░   ░  ░░▓  ░░ ▒░ ░\n" +
						   " ▒░▒   ░   ▒   ▒▒ ░  ░▒ ░ ▒░░  ░      ░ ▒ ░ ░ ░  ░\n" +
						   "  ░    ░   ░   ▒     ░░   ░ ░      ░    ▒ ░   ░   \n" +
						   "  ░            ░  ░   ░            ░    ░     ░  ░\n" +
						   "       ░                                     v1.0\n" +
						   "             Java RMI enumeration tool.\n" +
						   "               Written by Nicky Bloor (@NickstaDB)\n\n" +
						   "Warning: BaRMIe was written to aid security professionals in identifying the\n" +
						   "         insecure use of RMI services on systems which the user has prior\n" +
						   "         permission to attack. BaRMIe must be used in accordance with all\n" +
						   "         relevant laws. Failure to do so could lead to your prosecution.\n" +
						   "         The developers assume no liability and are not responsible for any\n" +
						   "         misuse or damage caused by this program.\n");
		
		//Just print usage if command line is empty
		if(args.length == 0) {
			printUsage("");
			return;
		}
		
		//Parse command line options
		try {
			options = new ProgramOptions(args);
		} catch(BaRMIeIllegalArgumentException|BaRMIeInvalidPortException ex) {
			//Something wrong with the command line
			printUsage(ex.getMessage());
			return;
		}
		
		//Delegate to the relevant program mode
		switch(options.getExecutionMode()) {
			case "-enum":
				//Enumerate RMI endpoints
				new EnumerationMode(options).run();
				break;
				
			case "-attack":
				//Attack RMI endpoints
				new AttackMode(options).run();
				break;
				
			default:
				//Shouldn't happen, whatever...
				printUsage("Invalid mode specified.");
		}
	}
	
	/*******************
	 * Print a usage message.
	 * 
	 * @param error Error message, e.g. if there was an issue with command line options.
	 ******************/
	private static void printUsage(String error) {
		System.out.println((error.equals("") ? "" : "Error: " + error + "\n\n") +
						   "Usage:\n" +
						   "  BaRMIe -enum [options] [host] [port]\n" +
						   "    Enumerate RMI services on the given endpoint(s).\n" +
						   "    Note: if -enum is not specified, this is the default mode.\n" +
						   "  BaRMIe -attack [options] [host] [port]\n" +
						   "    Enumerate and attack the given target(s).\n" +
						   "Options:\n" +
						   "  --threads  The number of threads to use for enumeration (default 10).\n" +
						   "  --timeout  The timeout for blocking socket operations (default 5,000ms).\n" +
						   "  --targets  A file containing targets to scan.\n" +
						   "             The file should contain a single host or space-separated\n" +
						   "             host and port pair per line.\n" +
						   "             Alternatively, all nmap output formats are supported, BaRMIe will\n" +
						   "             parse nmap output for port 1099, 'rmiregistry', or 'Java RMI'\n" +
						   "             services to target.\n" +
						   "             Note: [host] [port] not supported when --targets is used.\n" +
						   "Reliability:\n" +
						   "    A +/- system is used to indicate attack reliability as follows:\n" +
						   "      [+  ]: Indicates an application-specific attack\n" +
						   "      [-  ]: Indicates a JRE attack\n" +
						   "      [ + ]: Attack insecure methods (such as 'writeFile' without auth)\n" +
						   "      [ - ]: Attack Java deserialization (i.e. Object parameters)\n" +
						   "      [  +]: Does not require non-default dependencies\n" +
						   "      [  -]: Non-default dependencies are required"
		);
	}
}
