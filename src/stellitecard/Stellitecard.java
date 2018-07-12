/**
 Copyright (c) 2014-2018, The Stellite Project

 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification, are
 permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this list of
    conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice, this list
    of conditions and the following disclaimer in the documentation and/or other
    materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors may be
    used to endorse or promote products derived from this software without specific
    prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * @author ereddon - eralinkindo@gmail.com 
 *
 */
public class Stellitecard extends Applet {

	// user credentials are meant to be hardcoded for security, at least for now. Example below for user email "test@xtl.cash" and password "password"
	
	private static final byte[] userEmail = {'t','e','s','t','@','x','t','l','.','c','a','s','h'};
	private static final byte[] userPassword = {'p','a','s','s','w','o','r','d'};	
	private static byte[] userCredentials;
	
	// using static public key for now -- DO NOT CHANGE BELOW THIS LINE
	private static final byte[] stellitePubKey = {-70, -101, -25, 125, -61, -1, 64, -63, 43, 102, 111, 70, 32, -88, -18, 103, -41, -111, -39, 19, -89, -44, -125, 126, 111, -23, 12, 50, 111, -50, -61, -9, -84, 108, 86, -65, 108, -41, -47, -38, -7, 101, -41, -44, 7, -70, -7, 48, 53, -103, 54, 99, 65, -71, -78, 80, -27, -62, -96, 126, -108, -85, -48, -115, -50, 124, -121, -13, -119, -96, -126, 100, 65, -78, 13, -79, -109, 89, -12, -46, 5, 124, 72, 44, -56, -18, 111, -84, 9, -9, -21, 80, 61, -14, 57, -107, 80, -102, -37, 107, 78, -35, -121, -108, -71, 41, 65, -109, 6, 86, -112, 63, 9, -77, -108, -71, 33, 82, -46, -28, 122, -44, -59, 35, -92, 81, -28, -43, -17, -98, -73, 30, 79, -50, -99, 48, -22, 77, 14, -40, 25, 65, 3, 68, -110, -74, 110, 98, -89, 77, -121, -79, 111, -61, -104, -98, -115, -112, -28, -36, -26, -65, 72, -40, -127, 115, 29, 76, 126, 52, -56, 116, -62, 41, 85, 65, 81, 22, -36, -31, -39, 101, 127, 106, 70, -84, -36, 20, 6, 99, -68, -91, -74, 125, -57, 15, -21, -16, 76, 78, -105, 16, 36, -39, -2, -45, 38, -98, -64, -107, -42, -87, 60, -15, -45, -61, 54, -84, 89, -90, 0, -51, 0, -64, 82, 125, 46, 72, 106, -71, 52, -75, -80, 16, 113, 52, 104, 110, 40, -7, -71, 73, 80, -107, 121, 96, -100, -48, -11, 67, 28, 112, 101, 109, 82, -25, 1, 0, 1};	
	private static final byte INS_GET_VERSION		       = (byte)0x30;
	private static final byte INS_GET_ID			       = (byte)0x33;
	private static final byte INS_REQ_TXS_CIPHER           = (byte)0x31;
	private static final byte INS_VERIFY_TXS_CIPHER        = (byte)0x32;	
	
	private static short pubKeyOffset = (short)256;
	
	private static byte[] userHash;
	private static byte[] RamBuffer;
	private static final short RAM_BUFFER_1 = (short) 1;
	private static final short RAM_BUFFER_4 = (short) 4;
	private static final short RAM_BUFFER_16 = (short) 16;
	private static final short RAM_BUFFER_20 = (short) 20;
	private static final short RAM_BUFFER_256 = (short) 256;
	
	public static final byte TXS_OK = 0;
	public static final byte TXS_ERROR_SIGNATURE = 1;
	
	public static final byte TXS_TYPE_TRANSFER = 0;
	public static final byte TXS_TYPE_RESERVED = 1;	
	
	// note the maximum card txs is capped at 4 billion times
	private static byte invocationCounterHi;
	private static byte invocationCounterLo;
	private static RandomData RandomSalts;
	private static byte[] RnDBuffer;
	private static Cipher RSA2048Encryptor;
	private static Signature RSA2048Verificator;
	private static RSAPublicKey RSAPubKey;
	private static MessageDigest sha256;
	private static byte[] TXSResult;
	private static byte[] TXSType;
	private static byte[] TXSAmount;
	private static byte[] signedTxs;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new stellitecard.Stellitecard().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
		// objects initialization at applet installation
		RamBuffer = JCSystem.makeTransientByteArray(RAM_BUFFER_256, JCSystem.CLEAR_ON_RESET);
		signedTxs = JCSystem.makeTransientByteArray(RAM_BUFFER_256, JCSystem.CLEAR_ON_RESET);
		TXSAmount = JCSystem.makeTransientByteArray(RAM_BUFFER_4, JCSystem.CLEAR_ON_RESET);	
		RnDBuffer = JCSystem.makeTransientByteArray(RAM_BUFFER_16, JCSystem.CLEAR_ON_RESET);	
		TXSResult = JCSystem.makeTransientByteArray(RAM_BUFFER_1, JCSystem.CLEAR_ON_RESET);
		TXSType = JCSystem.makeTransientByteArray(RAM_BUFFER_1, JCSystem.CLEAR_ON_RESET);	
		userHash = JCSystem.makeTransientByteArray(RAM_BUFFER_20, JCSystem.CLEAR_ON_RESET);
		userCredentials = JCSystem.makeTransientByteArray((short)(userEmail.length + userPassword.length), JCSystem.CLEAR_ON_RESET);
		RandomSalts = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		RSA2048Encryptor = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		RSA2048Verificator = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		RSAPubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
		// objects initial value 
		invocationCounterLo = 0;	
		invocationCounterHi = 0;
		RSAPubKey.setModulus(stellitePubKey, (short)0, pubKeyOffset);
		RSAPubKey.setExponent(stellitePubKey, pubKeyOffset, (short)3);
		sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);	
		RSA2048Encryptor.init(RSAPubKey, Cipher.MODE_ENCRYPT);
		RSA2048Verificator.init(RSAPubKey, Signature.MODE_VERIFY);
	}
	
	/*
	 *
	 * TXS Encryption 
	 * 
	 */
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
		// filter by length
		if(bDataLength != 0x66){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}		
		apdu.setIncomingAndReceive();
		Util.arrayCopyNonAtomic(apduBuffer, (short)5, RamBuffer, (short)0, (short)(64+1+4));
		// buffer txs type and txs amount for future use
		Util.arrayCopyNonAtomic(RamBuffer, (short)0, TXSType, (short)0,(short)TXSType.length);
		Util.arrayCopyNonAtomic(RamBuffer, (short)1, TXSAmount, (short)0,(short)TXSAmount.length);
		// calculate user hash
		Util.arrayCopyNonAtomic(userEmail, (short)0, userCredentials, (short)0,(short)userEmail.length);
		Util.arrayCopyNonAtomic(userPassword, (short)0, userCredentials, (short)userEmail.length,(short)userPassword.length);
		sha256.doFinal(userCredentials, (short)0, (short)userCredentials.length, userHash, (short)0);
		Util.arrayCopyNonAtomic(userHash, (short)0, RamBuffer, (short)(64+1+4),(short)userHash.length);
		// get random number
		RandomSalts.generateData(RnDBuffer, (short)0, (short)16);		
		Util.arrayCopyNonAtomic(RnDBuffer, (short)0, RamBuffer, (short)(64+1+4+(short)userHash.length),(short)RnDBuffer.length);
		// encrypt all
		RSA2048Encryptor.doFinal(RamBuffer, (short)0, (short)128, RamBuffer, (short)0);	
		// send the result 
		Util.arrayCopyNonAtomic(RamBuffer, (short)0, apduBuffer, (short)0, (short)RamBuffer.length);
		apdu.setOutgoingAndSend((short)0, (short)RamBuffer.length); 		
	}	
	
	/*
	 * 
	 * TXS Verification 
	 * 
	 */
	private void stelliteTxsVerify(APDU apdu){
		short P1, P2,bDataLength;
		byte[] apduBuffer = apdu.getBuffer();
		P1 = apduBuffer[ISO7816.OFFSET_P1];
		P2 = apduBuffer[ISO7816.OFFSET_P2];
		if((byte)0 != P1)
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		bDataLength = (short)((short)0x00FF & apduBuffer[ISO7816.OFFSET_LC]);
		// filter by length
		if(bDataLength != 0x80){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		apdu.setIncomingAndReceive();
		Util.arrayCopyNonAtomic(apduBuffer, (short)5, RamBuffer, (short)0, bDataLength);
		// get signature partially by using P2 as flag
		if(P2==0x00){
			// P2 zero mean first 128 byte signature
			Util.arrayCopyNonAtomic(RamBuffer, (short)0, signedTxs, (short) 0, (short)(signedTxs.length/2));
		}else{
			// P2 other than zero mean last 128 byte signature
			Util.arrayCopyNonAtomic(RamBuffer, (short)0, signedTxs, (short)(signedTxs.length/2), (short)(signedTxs.length/2));
			// construct (userhash + txs type + txs amount + random) on RAM
			Util.arrayCopyNonAtomic(userHash, (short)0, RamBuffer, (short) 0, (short)userHash.length);
			Util.arrayCopyNonAtomic(TXSType, (short)0, RamBuffer, (short) userHash.length, (short)TXSType.length);
			Util.arrayCopyNonAtomic(TXSAmount, (short)0, RamBuffer, (short) (userHash.length + TXSType.length), (short)TXSAmount.length);
			Util.arrayCopyNonAtomic(RnDBuffer, (short)0, RamBuffer, (short) (userHash.length + TXSType.length + TXSAmount.length), (short)RnDBuffer.length);
			// verify signature
			boolean ret = RSA2048Verificator.verify(RamBuffer, (short)0, (short)(userHash.length + TXSType.length + TXSAmount.length + RnDBuffer.length), signedTxs, (short)0, (short)signedTxs.length);
			if(ret==false){
				TXSResult[0] = TXS_ERROR_SIGNATURE;
			}else{
				TXSResult[0] = TXS_OK;
			}
			// increment invocation counter
			invocationCounterLo++;
			if(invocationCounterLo==0){
				invocationCounterHi++;
			}
			// construct (txs result + credential hash + incremented invocation counter + random)
			Util.arrayFillNonAtomic(RamBuffer, (short) 0, (short)RamBuffer.length, (byte) 0);
			Util.arrayCopyNonAtomic(userHash, (short)0, RamBuffer, (short) 0, (short)userHash.length);
			Util.arrayCopyNonAtomic(TXSResult, (short)0, RamBuffer, (short) userHash.length, (short)TXSResult.length);
			Util.arrayCopyNonAtomic(RnDBuffer, (short)0, RamBuffer, (short) (userHash.length + TXSResult.length), (short)RnDBuffer.length);
			RamBuffer[(userHash.length + TXSResult.length + RnDBuffer.length)+3]=(byte)(invocationCounterLo & 0xff);
			RamBuffer[(userHash.length + TXSResult.length + RnDBuffer.length)+2]=(byte)((invocationCounterLo >> 8) & 0xff);
			RamBuffer[(userHash.length + TXSResult.length + RnDBuffer.length)+1]=(byte)(invocationCounterHi & 0xff);
			RamBuffer[(userHash.length + TXSResult.length + RnDBuffer.length)]=(byte)((invocationCounterHi >> 8) & 0xff);
			// encrypt
			RSA2048Encryptor.doFinal(RamBuffer, (short)0, (short)128, RamBuffer, (short)0);
			// send the encrypted data
			Util.arrayCopyNonAtomic(RamBuffer, (short)0, apduBuffer, (short)0, (short)RamBuffer.length);
			apdu.setOutgoingAndSend((short)0, (short)RamBuffer.length);			
		}
	}		
	
	/*
	 * 
	 *  GET VERSION
	 * 
	 */
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
	
	/*
	 * 
	 *  GET VERSION
	 * 
	 */
	private void getUserID(APDU apdu)
	{
		short P1, P2;
		
		byte[] apduBuffer = apdu.getBuffer();
		P1 = apduBuffer[ISO7816.OFFSET_P1];
		P2 = apduBuffer[ISO7816.OFFSET_P2];
		
		if(((byte)0x00 != P1) && ((byte)0x00 != P2))
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		Util.arrayCopyNonAtomic(userEmail, (short)0, apduBuffer, (short)0, (short)userEmail.length);
		apdu.setOutgoingAndSend((short)0, (short)userEmail.length);		
	}
	
	/*
	 * 
	 * (non-Javadoc)
	 * @see javacard.framework.Applet#process(javacard.framework.APDU)
	 */
	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) INS_GET_VERSION:
			getCardVersion(apdu);
			break;	
		case (byte) INS_REQ_TXS_CIPHER:
			stelliteTxsEncrypt(apdu);
			break;	
		case (byte) INS_VERIFY_TXS_CIPHER:
			stelliteTxsVerify(apdu);
			break;	
		case (byte) INS_GET_ID:
			getUserID(apdu);
			break;				
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}