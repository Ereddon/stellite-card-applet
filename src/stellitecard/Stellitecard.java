/**
 * 
 */
package stellitecard;

import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * @author 
 *
 */
public class Stellitecard extends Applet {
	
	private static byte[] PubKeySets;
	private static byte[] RamBuffer;
	private static final short RAM_BUFFER_32 = (short) 32;
	private static final short RAM_BUFFER_128 = (short) 128;
	private static final short RAM_BUFFER_256 = (short) 256;
	private static final short RAM_ZEROS = (short) 0;
	private static final short PUB_KEY_LEN = (short) 270;
	
	public static final byte TXS_OK = 0;
	public static final byte TXS_ERROR_SIGNATURE = 1;

	public static final byte TXS_TYPE_TRANSFER = 0;
	public static final byte TXS_TYPE_TOP_UP = 1;	
	
	// note the maximum card txs is capped at 65535 times
	private static short invocationCounter;
	private static RandomData RandomSalts;
	private static Cipher RSA2048Encryptor;
	private static Cipher RSA2048Verificator;
	private static RSAPublicKey RSAPubKey;
	private static byte[] userEmailHash;
	private static byte[] passwordHash;
	private static byte TXSResult;
	private static byte TXSType;
	private static byte[] TXSAmount;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// general purpose buffer to process data
		RamBuffer = JCSystem.makeTransientByteArray(RAM_BUFFER_256, JCSystem.CLEAR_ON_RESET);
		RandomSalts = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		RSA2048Encryptor = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		RSA2048Verificator = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		RSAPubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
		userEmailHash = new byte[RAM_BUFFER_32];
		passwordHash = new byte[RAM_BUFFER_32];
		TXSAmount = new byte[4];	
		
		// GP-compliant JavaCard applet registration
		new stellitecard.Stellitecard().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
		
		// reset ic at install applet
		invocationCounter = 0;	
		TXSResult = TXS_OK;
		TXSType = TXS_TYPE_TRANSFER;
		// server public key hardcoded here, RSA2048 has 256 byte key length
		// must be changed if the server update keys	
		PubKeySets = new byte[] {48, (byte) 130, 1, 10, 2, (byte) 130, 1, 1, 0, (byte)163, (byte)248, (byte)160, 76, 1, 27, 107, (byte)132, (byte)131, (byte)156, 110, (byte)195, 49, 124, 95, (byte)237, 58, (byte)248, (byte)130, (byte)249, (byte)149, 106, (byte)161, 75, (byte)129, (byte)217, (byte)180, (byte)232, 54, 10, 66, 123, (byte)245, (byte)233, 59, 66, (byte)174, (byte)215, 50, (byte)150, 60, (byte)242, (byte)249, 114, (byte)237, (byte)208, 123, 31, 110, (byte)201, 13, (byte)230, 75, 116, (byte)224, (byte)254, 37, (byte)140, 15, 56, 13, 117, (byte)158, 17, 89, (byte)246, (byte)162, 18, (byte)227, 44, 76, (byte)168, 30, 74, 6, 41, 88, 103, 111, (byte)165, (byte)133, 42, (byte)182, 41, (byte)218, 121, (byte)195, 71, (byte)186, 75, 27, 84, 33, (byte)160, (byte)235, (byte)214, (byte)130, 93, (byte)216, (byte)178, 54, (byte)200, 26, (byte)241, (byte)136, (byte)140, (byte)144, 126, 95, 126, (byte)196, (byte)164, (byte)185, 33, 17, 34, 29, 105, (byte)240, 82, 25, 0, (byte)241, 119, 127, (byte)151, 49, (byte)252, (byte)209, 114, 3, 69, 89, 105, 114, 73, 103, (byte)199, (byte)242, 46, 9, (byte)229, (byte)190, (byte)141, 84, (byte)207, 12, (byte)219, 121, 94, 97, (byte)169, 2, (byte)178, 54, (byte)242, (byte)196, (byte)195, (byte)228, 116, 29, 82, (byte)233, (byte)205, (byte)232, 67, (byte)169, 11, (byte)246, (byte)174, (byte)192, (byte)154, (byte)195, (byte)204, 106, (byte)202, (byte)158, 113, (byte)172, (byte)186, (byte)219, (byte)251, 124, (byte)251, (byte)200, (byte)174, (byte)153, (byte)154, 62, (byte)135, 63, (byte)225, 78, (byte)196, (byte)179, 5, 40, (byte)201, (byte)232, 99, (byte)211, (byte)219, 102, 45, 21, (byte)233, (byte)130, 126, 99, (byte)150, 10, 12, (byte)203, 31, (byte)203, (byte)211, 92, (byte)255, 61, (byte)175, (byte)142, 31, (byte)220, 9, (byte)177, (byte)191, (byte)167, 58, (byte)203, 124, 82, 69, (byte)248, (byte)167, 102, 49, 52, 54, 12, (byte)236, 49, (byte)149, (byte)166, 88, (byte)142, (byte)240, 21, 42, 12, (byte)187, (byte)247, (byte)202, (byte)158, (byte)148, (byte)249, 61, 2, 3, 1, 0, 1};


	}

	//reads the key from the buffer and stores it inside the key object
	private final short deserializeKey(RSAPublicKey key, byte[] buffer, short offset) {
	    short expLen = Util.getShort(buffer, offset);
	    key.setExponent(buffer, (short) (offset + 2), expLen);
	    short modLen = Util.getShort(buffer, (short) (offset + 2 + expLen));
	    key.setModulus(buffer, (short) (offset + 4 + expLen), modLen);
	    return (short) (4 + expLen + modLen);
	}
	
	//reads the key object and stores it into the buffer
	private final short serializeKey(RSAPublicKey key, byte[] buffer, short offset) {
	    short expLen = key.getExponent(buffer, (short) (offset + 2));
	    Util.setShort(buffer, offset, expLen);
	    short modLen = key.getModulus(buffer, (short) (offset + 4 + expLen));
	    Util.setShort(buffer, (short)(offset + 2 + expLen), modLen);
	    return (short) (4 + expLen + modLen);
	}
	
	private void process_GetCardVersion(APDU apdu)
	{
		byte[] SAMInfo = {'S','t','e','l','l','i','t','e','C','a','r','d','-','v','1','.','0'};
		short SAM_INFO_MAX = (short) 17;
		short P1, P2;
		
		byte[] apduBuffer = apdu.getBuffer();
		P1 = apduBuffer[ISO7816.OFFSET_P1];
		P2 = apduBuffer[ISO7816.OFFSET_P2];
	
		if(((byte)0x00 != P1) && ((byte)0x00 != P2))
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		Util.arrayCopyNonAtomic(SAMInfo, (short)0, apduBuffer, (short)0, SAM_INFO_MAX);
		apdu.setOutgoingAndSend((short)0, SAM_INFO_MAX);		
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
		case (byte) 0x10:
			break;
		case (byte) 0x60:
			process_GetCardVersion(apdu);
			break;		
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}