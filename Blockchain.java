/**
 *
 */
package Blockchain;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;

import javacardx.crypto.*;
import javacard.security.*;

/**
 * @author Administrator
 *
 */
public class Blockchain extends Applet {
	private byte[] stuNum = {0x32,0x30,0x31,0x35,0x32,0x31,0x31,0x30,0x32,0x31};//2015211021
	private byte[] gb2312 = {(byte)0x04,(byte) 0xD5,(byte) 0xC5,(byte)0xEA,(byte)0xBF};//长度0x04,张昕--D5C5 EABF
	private static MessageDigest messageDigest;
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new Blockchain().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
		messageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, true);

	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0x81://使用10个字节ASCII码表示学号//send 80810000000a
		{
			byte[] buffer=apdu.getBuffer();
			short le=apdu.setOutgoing();
			if(le<10)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			apdu.setOutgoingLength((byte)10);
			buffer[0]=stuNum[0];
			buffer[1]=stuNum[1];
			buffer[2]=stuNum[2];
			buffer[3]=stuNum[3];
			buffer[4]=stuNum[4];
			buffer[5]=stuNum[5];
			buffer[6]=stuNum[6];
			buffer[7]=stuNum[7];
			buffer[8]=stuNum[8];
			buffer[9]=stuNum[9];
			apdu.sendBytes((short)0,(short)10);
			break;
		}
		case (byte) 0x82://使用GB2312编码返回LV方式//send 80820000007f
		{
			byte[] buffer_82=apdu.getBuffer();
			short le_82=apdu.setOutgoing();
			if(le_82<10)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			apdu.setOutgoingLength((byte)5);
			buffer_82[0]=gb2312[0];
			buffer_82[1]=gb2312[1];
			buffer_82[2]=gb2312[2];
			buffer_82[3]=gb2312[3];
			buffer_82[4]=gb2312[4];
			apdu.sendBytes((short)0,(short)5);
			break;
		}
		case (byte) 0x83://send 808309000568656c6c6f7f mineBlock
		{
			byte[] buffer_83=apdu.getBuffer();
			byte Level = buffer_83[ISO7816.OFFSET_P1];
			byte DataOffset = ISO7816.OFFSET_CDATA;
			byte DataLength = buffer_83[4];

			byte[] result = mineBlock(Level, buffer_83, DataOffset, DataLength);

			//set output mode
			for(short i = 0; i < result.length; i++)
			{
				buffer_83[i]  = result[i];
			}
			short le_83=apdu.setOutgoing();
			apdu.setOutgoingLength((byte)result.length);
			apdu.sendBytes((short)0,(short)result.length);
			break;
		}
		case (byte) 0x84://debug
		{
			//send 80840000206162636462636465636465666465666765666768666768696768696a68696a6b7f
			//the input of  Ripemd160 must be 32 bytes

			byte[] buffer_84=apdu.getBuffer();
			short le_84=apdu.setOutgoing();


			byte[] debugBuffer = new byte[buffer_84[4]];
			byte[] debugResult = new byte[20];
			byte[] AddrResult;

			for(short i = 0;i < buffer_84[4]; i++)
			{
				debugBuffer[i] = buffer_84[(short)5 + i];
			}

			Ripemd160.hash32(debugBuffer, (short)0, debugResult, (short)0, new byte[64], (short)0);

			byte resultLen = (byte)(debugResult).length;
			apdu.setOutgoingLength(resultLen);
			for(short i = 0; i < resultLen; i++)
			{
				buffer_84[i]  = debugResult[i];
			}
			apdu.sendBytes((short)0,(short)resultLen);
			break;

		}
		case (byte) 0x85://send
		{
			byte[] buffer_85=apdu.getBuffer();
			byte DataOffset = ISO7816.OFFSET_CDATA;
			byte DataLength = buffer_85[4];

			byte[] result = generateAddr(buffer_85, DataOffset, DataLength);

			//set output mode
			short resultLen = (short)(result).length;
			for(short i = 0; i < resultLen; i++)
			{
				buffer_85[i]  = result[i];
			}
			short le_85=apdu.setOutgoing();
			apdu.setOutgoingLength(resultLen);
			apdu.sendBytes((short)0,resultLen);
			break;

		}

		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	private static byte[] mineBlock(byte Level, byte[] data, byte offset, short dataLen)
	{
		byte[] data_rand = new byte[dataLen + 2];
		short rand = 0;
		byte[] SHA_result = new byte[20];
		byte level_h = 0;
		byte level_l = 0;
		boolean rightHash = false;
		boolean rightHashHigh = true;
		boolean rightHashLow = true;


		byte[] debugBuffer = new byte[dataLen];
		byte[] debugResult;

		//copy data to data_rand
		for(short i = 0;i < dataLen; i++)
		{
			data_rand[i] = data[offset + i];
		}
		//try SHA_256 and increase rand
		level_h = (byte) (Level >>> 3);
		level_l = (byte) (Level &   7);
		while(rand <= (short)32767 && !rightHash)
		{
			rightHashHigh = true;
			rightHashLow = true;
			//increase rand
			rand = (short) (rand + (short)1);
			data_rand[0 + dataLen]=(byte)(rand>>8);
			data_rand[1 + dataLen]=(byte)(rand&0xff);

			//try SHA_256
			SHA_256(data_rand,(short)(dataLen+2),SHA_result);

			//judge
			for(byte cnt = 0;cnt < level_h && rightHashHigh;cnt++)
			{
				if(SHA_result[cnt] == 0x00)
				{continue;}
				else
				{rightHashHigh = false;}
			}

			if((SHA_result[level_h] >>> (8-level_l)) == (byte)0)
			{rightHashLow = true;}
			else
			{rightHashLow =false;}

			rightHash = rightHashHigh && rightHashLow;
		}
		if(rand <= (short)32767)
		{
			//success
			return data_rand;
		}
		else//rightHash
		{
			return null;
			// lose
		}

	}
	private static byte[] generateAddr(byte[] data, short offset, short dataLen)
	{
		byte[] SHA_In = new byte[dataLen];
		byte[] SHA_Result = new byte[20];
		byte[] SHA2RIP = new byte[32];
		byte[] RIP_Result = new byte[20];
		byte[] Base58_Result;

		for(short i = 0;i < dataLen; i++)
		{
			SHA_In[i] = data[offset + i];
		}
		SHA_256(SHA_In,(short)(dataLen),SHA_Result);//1.SHA_256(data)

		for(byte i = 0; i < 32;i++)//exchange SHA_Result to a byte[32]
		{
			if(i < 20){SHA2RIP[i] = SHA_Result[i];}
			else{SHA2RIP[i] = 0;}
		}
		//2.Ripemd160(SHA_256_result)
		Ripemd160.hash32(SHA2RIP, (short)0, RIP_Result, (short)0, new byte[64], (short)0);
		//3.Base58(Ripemd160_result)
		Base58_Result = Byte58Check(RIP_Result,(byte)20);
		return Base58_Result;
	}

	private static void SHA_256(byte[] data, short dataLen,byte[] SHA_result)
	{
		messageDigest.doFinal(data, (short)0, dataLen, SHA_result, (short)0);
	}
	private static byte[] Byte58Check(byte[] data, byte dataLen)
	{
		byte[] result = Base58.encode(data);
		return result;
	}









}
