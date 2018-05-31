/**
 *
 */
package java3des;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import javacard.framework.ISO7816;
/**
 * @author Administrator
 *
 */
public class java3des extends Applet {
	byte [] Random;
	byte [] ciphertext = new byte[256];
	byte [] translation = new byte[256];
	private DESKey deskey;
	Cipher CipherObj;

	private byte[] keyData1 = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};//密钥
	private byte[] keyData2 = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18};
	private byte[] keyData3 = {0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28};

	protected java3des() {
		register();
	}
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new java3des();
	}

	public void process(APDU apdu)
	{
		byte []buffer = apdu.getBuffer();
		if(buffer[ISO7816.OFFSET_CLA]==0 && buffer[ISO7816.OFFSET_INS]==(byte)(0xa4))
		{
			return;
		}
		// Good practice: Return 9000 on SELECT
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) ///select |bupt.3des.1
		{
			case (byte) 0x84://send 0084000000
				getRandom();//return 8 bytes random
				Util.arrayCopyNonAtomic(Random, (short)0, buffer, (short)0, (short)8);
				apdu.setOutgoingAndSend((short)0, (short)8);
				break;
			case (byte) 0x83://send 0083000008 D4AA3503EC117A56 7F
				apdu.setIncomingAndReceive();
				encrypt(buffer);//加密
				Util.arrayCopyNonAtomic(ciphertext, (short)16, buffer, (short)0, (short)8);
				apdu.setOutgoingAndSend((short)0, (short)8);
				break;
			case (byte) 0x82://send 0082000008 DCC74C5B43340FB7 7F
				apdu.setIncomingAndReceive();
				doAuthentication(buffer);//解密
				break;
			default:
				// good practice: If you don't know the INStruction, say so:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	}
	}
	private void encrypt(byte[] buffer)
	{
		deskey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		deskey.setKey(keyData1, (short)0);
		CipherObj = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M1, false);
		CipherObj.init(deskey, Cipher.MODE_ENCRYPT);

		CipherObj.doFinal(buffer, (short)5, (short)8, ciphertext, (short)0);
		deskey.setKey(keyData2, (short)0);
		CipherObj = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M1, false);
		CipherObj.init(deskey, Cipher.MODE_DECRYPT);

		CipherObj.doFinal(ciphertext, (short)0, (short)8, ciphertext, (short)8);
		deskey.setKey(keyData3, (short)0);
		CipherObj = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M1, false);
		CipherObj.init(deskey, Cipher.MODE_ENCRYPT);
		CipherObj.doFinal(ciphertext, (short)8, (short)8, ciphertext, (short)16);
	}
	private void doAuthentication(byte[] buffer)
	{
		deskey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);

		deskey.setKey(keyData3, (short)0);

		CipherObj = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M1, false);

		CipherObj.init(deskey, Cipher.MODE_DECRYPT);

		CipherObj.doFinal(buffer, (short)5, (short)8, translation, (short)0);

		deskey.setKey(keyData2, (short)0);

		CipherObj = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M1, false);

		CipherObj.init(deskey, Cipher.MODE_ENCRYPT);
		
		CipherObj.doFinal(translation, (short)0, (short)8, translation, (short)8);

		deskey.setKey(keyData1, (short)0);

		CipherObj = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M1, false);

		CipherObj.init(deskey, Cipher.MODE_DECRYPT);

		CipherObj.doFinal(translation, (short)8, (short)8, translation, (short)16);
		if(Util.arrayCompare(translation, (short)16, Random, (short)0, (short)8)!=0)
		{
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
	}
	private void getRandom()//获取随机数
	{
		if(Random == null)
		{
			Random = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		}
		RandomData ICC = RandomData.getInstance((byte)RandomData.ALG_PSEUDO_RANDOM);
		ICC.setSeed(Random, (short)0, (short)8);
		ICC.generateData(Random, (short)0, (short)8);
	}


}
