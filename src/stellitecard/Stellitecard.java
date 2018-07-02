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
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacard.security.CryptoException;

/**
 * @author 
 *
 */
public class Stellitecard extends Applet {
	
	// user credentials are meant to be hardcoded for security
	private static final byte[] userEmail = {'t','e','s','t','@','x','t','l','.','c','a','s','h',};
	private static final byte[] userPassword = {'p','a','s','s','w','o','r','d'};
	private static byte[] userHash;
	// stellitepay public key
	private static final byte[] stellitePubKey = {48, (byte) 130, 1, 10, 2, (byte) 130, 1, 1, 0, (byte)163, (byte)248, (byte)160, 76, 1, 27, 107, (byte)132, (byte)131, (byte)156, 110, (byte)195, 49, 124, 95, (byte)237, 58, (byte)248, (byte)130, (byte)249, (byte)149, 106, (byte)161, 75, (byte)129, (byte)217, (byte)180, (byte)232, 54, 10, 66, 123, (byte)245, (byte)233, 59, 66, (byte)174, (byte)215, 50, (byte)150, 60, (byte)242, (byte)249, 114, (byte)237, (byte)208, 123, 31, 110, (byte)201, 13, (byte)230, 75, 116, (byte)224, (byte)254, 37, (byte)140, 15, 56, 13, 117, (byte)158, 17, 89, (byte)246, (byte)162, 18, (byte)227, 44, 76, (byte)168, 30, 74, 6, 41, 88, 103, 111, (byte)165, (byte)133, 42, (byte)182, 41, (byte)218, 121, (byte)195, 71, (byte)186, 75, 27, 84, 33, (byte)160, (byte)235, (byte)214, (byte)130, 93, (byte)216, (byte)178, 54, (byte)200, 26, (byte)241, (byte)136, (byte)140, (byte)144, 126, 95, 126, (byte)196, (byte)164, (byte)185, 33, 17, 34, 29, 105, (byte)240, 82, 25, 0, (byte)241, 119, 127, (byte)151, 49, (byte)252, (byte)209, 114, 3, 69, 89, 105, 114, 73, 103, (byte)199, (byte)242, 46, 9, (byte)229, (byte)190, (byte)141, 84, (byte)207, 12, (byte)219, 121, 94, 97, (byte)169, 2, (byte)178, 54, (byte)242, (byte)196, (byte)195, (byte)228, 116, 29, 82, (byte)233, (byte)205, (byte)232, 67, (byte)169, 11, (byte)246, (byte)174, (byte)192, (byte)154, (byte)195, (byte)204, 106, (byte)202, (byte)158, 113, (byte)172, (byte)186, (byte)219, (byte)251, 124, (byte)251, (byte)200, (byte)174, (byte)153, (byte)154, 62, (byte)135, 63, (byte)225, 78, (byte)196, (byte)179, 5, 40, (byte)201, (byte)232, 99, (byte)211, (byte)219, 102, 45, 21, (byte)233, (byte)130, 126, 99, (byte)150, 10, 12, (byte)203, 31, (byte)203, (byte)211, 92, (byte)255, 61, (byte)175, (byte)142, 31, (byte)220, 9, (byte)177, (byte)191, (byte)167, 58, (byte)203, 124, 82, 69, (byte)248, (byte)167, 102, 49, 52, 54, 12, (byte)236, 49, (byte)149, (byte)166, 88, (byte)142, (byte)240, 21, 42, 12, (byte)187, (byte)247, (byte)202, (byte)158, (byte)148, (byte)249, 61, 2, 3, 1, 0, 1};
	
	private static final byte INS_GET_VERSION		       = (byte)0x30;
    private static final byte INS_REQ_TXS_CIPHER           = (byte)0x31;
    private static final byte INS_VERIFY_TXS_CIPHER        = (byte)0x32;	
    
    private static short pubKeyOffset = (short)256;
	
	private static byte[] RamBuffer;
	private static byte[] CipherBuffer;
	private static final short RAM_BUFFER_1 = (short) 1;
	private static final short RAM_BUFFER_2 = (short) 2;
	private static final short RAM_BUFFER_4 = (short) 4;
	private static final short RAM_BUFFER_8 = (short) 8;
	private static final short RAM_BUFFER_16 = (short) 16;
	private static final short RAM_BUFFER_32 = (short) 32;
	private static final short RAM_BUFFER_128 = (short) 128;
	private static final short RAM_BUFFER_256 = (short) 256;
	
	public static final byte TXS_OK = 0;
	public static final byte TXS_ERROR_SIGNATURE = 1;

	public static final byte TXS_TYPE_TRANSFER = 0;
	public static final byte TXS_TYPE_RESERVED = 1;	
	
	// note the maximum card txs is capped at 4 billion times
	private static short invocationCounterHi;
	private static short invocationCounterLo;
	private static RandomData RandomSalts;
	private static byte[] RnDBuffer;
	private static Cipher RSA2048Encryptor;
	private static Signature RSA2048Verificator;
	private static RSAPublicKey RSAPubKey;
	private static MessageDigest sha256;
	private static byte[] TXSResult;
	private static byte[] TXSType;
	private static byte[] TXSAmount;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new stellitecard.Stellitecard().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
		// objects initialization at applet installation
		RamBuffer = JCSystem.makeTransientByteArray(RAM_BUFFER_256, JCSystem.CLEAR_ON_RESET);
		TXSAmount = JCSystem.makeTransientByteArray(RAM_BUFFER_4, JCSystem.CLEAR_ON_RESET);	
		RnDBuffer = JCSystem.makeTransientByteArray(RAM_BUFFER_16, JCSystem.CLEAR_ON_RESET);	
		TXSResult = JCSystem.makeTransientByteArray(RAM_BUFFER_1, JCSystem.CLEAR_ON_RESET);
		TXSType = JCSystem.makeTransientByteArray(RAM_BUFFER_1, JCSystem.CLEAR_ON_RESET);	
		userHash = JCSystem.makeTransientByteArray(RAM_BUFFER_32, JCSystem.CLEAR_ON_RESET);
		RandomSalts = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		RSA2048Encryptor = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
		RSA2048Verificator = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		RSAPubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
		// objects initial value 
		invocationCounterLo = 0;	
		invocationCounterHi = 0;
		RSAPubKey.setModulus(stellitePubKey, (short)0, pubKeyOffset);
		RSAPubKey.setExponent(stellitePubKey, pubKeyOffset, (short)3);
		sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		Util.arrayCopyNonAtomic(userEmail, (short)0, userHash, (short)0, (short)userEmail.length);
		Util.arrayCopyNonAtomic(userPassword, (short)0, userHash, (short)userEmail.length, (short)userPassword.length);
		sha256.doFinal(userHash, (short)0, (short)userHash.length, userHash, (short)0);	
		RSA2048Encryptor.init(RSAPubKey, Cipher.MODE_ENCRYPT);
		RSA2048Verificator.init(RSAPubKey, Signature.MODE_VERIFY);
	}
	
	private void stelliteTxsEncrypt(APDU apdu){
		short P1, P2,bDataLength;
		byte[] apduBuffer = apdu.getBuffer();
		P1 = apduBuffer[ISO7816.OFFSET_P1];
		P2 = apduBuffer[ISO7816.OFFSET_P2];
		if(((byte)0 != P1) && ((byte)0 != P2))
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		bDataLength = (short)((short)0x00FF & apduBuffer[ISO7816.OFFSET_LC]);
		apdu.setIncomingAndReceive();
		Util.arrayFillNonAtomic(RamBuffer, (short) 0, (short)RamBuffer.length, (byte) 0);
		Util.arrayCopyNonAtomic(apduBuffer, (short)5, RamBuffer, (short)0, bDataLength);		
		// TODO get random number
		RandomSalts.generateData(RnDBuffer, (short)0, (short)16);
		// TODO construct (txsdestaddr+txstype+txsamount+credentialhash+random) on RAM
		Util.arrayCopyNonAtomic(TXSType, (short)0, RamBuffer, (short)97,(short)TXSType.length);
		Util.arrayCopyNonAtomic(TXSAmount, (short)0, RamBuffer, (short)(97+1),(short)TXSAmount.length);
		Util.arrayCopyNonAtomic(userHash, (short)0, RamBuffer, (short)(97+1+4),(short)userHash.length);
		Util.arrayCopyNonAtomic(RnDBuffer, (short)0, RamBuffer, (short)(97+1+4+(short)userHash.length),(short)RnDBuffer.length);
		// TODO encrypt all
	    RSA2048Encryptor.doFinal(RamBuffer, (short)0, (short)RamBuffer.length, RamBuffer, (short)0);	
		// TODO send the result 
		Util.arrayCopyNonAtomic(RamBuffer, (short)0, apduBuffer, (short)0, (short)RamBuffer.length);
        apdu.setOutgoingAndSend((short)0, (short)RamBuffer.length); 		
	}
	
	private void stelliteTxsVerify(APDU apdu){
		short P1, P2,bDataLength;
		byte[] apduBuffer = apdu.getBuffer();
		P1 = apduBuffer[ISO7816.OFFSET_P1];
		P2 = apduBuffer[ISO7816.OFFSET_P2];
		if(((byte)0 != P1) && ((byte)0 != P2))
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		bDataLength = (short)((short)0x00FF & apduBuffer[ISO7816.OFFSET_LC]);
		apdu.setIncomingAndReceive();
		Util.arrayCopyNonAtomic(apduBuffer, (short)5, RamBuffer, (short)0, bDataLength);
		// TODO get signature
		byte[] sig256 = new byte[256];
		Util.arrayCopyNonAtomic(RamBuffer, (short)0, sig256, (short) 0, (short)RamBuffer.length);
		// TODO construct (txs type + txs amount + random) on RAM
		Util.arrayFillNonAtomic(RamBuffer, (short) 0, (short)RamBuffer.length, (byte) 0);
		RamBuffer[0] = TXSType[0];
		Util.arrayCopyNonAtomic(TXSAmount, (short)0, RamBuffer, (short) 1, (short)TXSAmount.length);
		Util.arrayCopyNonAtomic(TXSAmount, (short)0, RamBuffer, (short) 1, (short)TXSAmount.length);
		Util.arrayCopyNonAtomic(RnDBuffer, (short)0, RamBuffer, (short) 5, (short)RnDBuffer.length);
		// TODO verify signature from (txs type + txs amount + random)
		boolean ret = RSA2048Verificator.verify(RamBuffer, (short)0, (short)RamBuffer.length, sig256, (short)0, (short)sig256.length);
        if(ret==false){
        	TXSResult[0] = TXS_ERROR_SIGNATURE;
        }else{
        	TXSResult[0] = TXS_OK;
        }
        // TODO increment invocation counter -- can't compile if below code is uncommented
//        if(invocationCounterLo==65534){
//        	invocationCounterHi++;
//        	invocationCounterLo=0;
//        }else{
        	invocationCounterLo++;
//        }        
        // TODO construct (credentialhash + txs result + incremented invocation counter + random)
        Util.arrayFillNonAtomic(RamBuffer, (short) 0, (short)RamBuffer.length, (byte) 0);
        Util.arrayCopyNonAtomic(userHash, (short)0, RamBuffer, (short) 0, (short)(userHash.length/2));
        RamBuffer[userHash.length/2] = TXSResult[0];
        RamBuffer[(userHash.length/2)+1]=(byte)(invocationCounterLo & 0xff);
        RamBuffer[(userHash.length/2)+2]=(byte)((invocationCounterLo >> 8) & 0xff);
        RamBuffer[(userHash.length/2)+3]=(byte)(invocationCounterHi & 0xff);
        RamBuffer[(userHash.length/2)+4]=(byte)((invocationCounterHi >> 8) & 0xff);
        Util.arrayCopyNonAtomic(RnDBuffer, (short)0, RamBuffer, (short)((userHash.length/2)+5), (short)RnDBuffer.length);
		// TODO encrypt (credentialhash + txs result + incremented invocation counter + random)
        RSA2048Encryptor.doFinal(RamBuffer, (short)0, (short)RamBuffer.length, RamBuffer, (short)0);
        // TODO send the encrypted data
		Util.arrayCopyNonAtomic(RamBuffer, (short)0, apduBuffer, (short)0, (short)RamBuffer.length);
		apdu.setOutgoingAndSend((short)0, (short)RamBuffer.length);
	}	
	
	private void getCardVersion(APDU apdu)
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
		case (byte) INS_GET_VERSION:
			getCardVersion(apdu);
//			genRsaKeyPair(apdu);
			break;	
		case (byte) INS_REQ_TXS_CIPHER:
			stelliteTxsEncrypt(apdu);
			break;	
		case (byte) INS_VERIFY_TXS_CIPHER:
			stelliteTxsVerify(apdu);
			break;				
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}