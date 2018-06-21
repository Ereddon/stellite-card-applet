/**
 * 
 */
package stellitecard;

import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.security.RandomData;


/**
 * @author 
 *
 */
public class Stellitecard extends Applet {
	
	private static final short RAM_BUFFER_16 = (short) 16;
	
	private static byte[] salts;
	private static byte[] authToken;
	private static long timeStamp;
	private static RandomData randomVal;
	
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new stellitecard.Stellitecard().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
		
		randomVal = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		salts = JCSystem.makeTransientByteArray(RAM_BUFFER_16, JCSystem.CLEAR_ON_RESET);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0x00:
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}