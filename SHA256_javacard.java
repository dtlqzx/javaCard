package src;

import java.io.*;
/*
 * Author	Shengqi Suizhu
 * Date		2014.12.07
 * See more detailed information in README.md
 *
 */
//pseudo-code used from  http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf P22
public class SHA256 {
	 int repeat_num=1;//groups
	 byte[] msg_binary;
	 byte[] str2;

	 byte[] H0="6a09e667".getBytes();
	 byte[] H1="bb67ae85".getBytes();
	 byte[] H2="3c6ef372".getBytes();
	 byte[] H3="a54ff53a".getBytes();
	 byte[] H4="510e527f".getBytes();
	 byte[] H5="9b05688c".getBytes();
	 byte[] H6="1f83d9ab".getBytes();
	 byte[] H7="5be0cd19".getBytes();
	 byte[] A,B,C,D,E,F,G,H;

	 byte[] output;
	 long begin;
	 long end;

	 byte[][] k=new byte[64][];

	 byte[][] K=
	   {"428a2f98".getBytes(),"71374491".getBytes(),"b5c0fbcf".getBytes(),"e9b5dba5".getBytes(),"3956c25b".getBytes(),"59f111f1".getBytes(),"923f82a4".getBytes(),"ab1c5ed5".getBytes(),
		"d807aa98".getBytes(),"12835b01".getBytes(),"243185be".getBytes(),"550c7dc3".getBytes(),"72be5d74".getBytes(),"80deb1fe".getBytes(),"9bdc06a7".getBytes(),"c19bf174".getBytes(),
		"e49b69c1".getBytes(),"efbe4786".getBytes(),"0fc19dc6".getBytes(),"240ca1cc".getBytes(),"2de92c6f".getBytes(),"4a7484aa".getBytes(),"5cb0a9dc".getBytes(),"76f988da".getBytes(),
		"983e5152".getBytes(),"a831c66d".getBytes(),"b00327c8".getBytes(),"bf597fc7".getBytes(),"c6e00bf3".getBytes(),"d5a79147".getBytes(),"06ca6351".getBytes(),"14292967".getBytes(),
		"27b70a85".getBytes(),"2e1b2138".getBytes(),"4d2c6dfc".getBytes(),"53380d13".getBytes(),"650a7354".getBytes(),"766a0abb".getBytes(),"81c2c92e".getBytes(),"92722c85".getBytes(),
		"a2bfe8a1".getBytes(),"a81a664b".getBytes(),"c24b8b70".getBytes(),"c76c51a3".getBytes(),"d192e819".getBytes(),"d6990624".getBytes(),"f40e3585".getBytes(),"106aa070".getBytes(),
		"19a4c116".getBytes(),"1e376c08".getBytes(),"2748774c".getBytes(),"34b0bcb5".getBytes(),"391c0cb3".getBytes(),"4ed8aa4a".getBytes(),"5b9cca4f".getBytes(),"682e6ff3".getBytes(),
		"748f82ee".getBytes(),"78a5636f".getBytes(),"84c87814".getBytes(),"8cc70208".getBytes(),"90befffa".getBytes(),"a4506ceb".getBytes(),"bef9a3f7".getBytes(),"c67178f2".getBytes()};

	 byte[] [] w=new byte[80][];

	private static byte[] subByteArray(byte[] byteArray,short start,short end)
	{
		short length = (short) (end - start);
		byte[] subArray = new byte[length];
		for(short i = 0; i < length; i++)
		{
			subArray[i] = byteArray[i + start];
		}
		return subArray;
	}
	private static byte[] subByteArray(byte[] byteArray,short start)
	{
		short len = (short) byteArray.length;
		short length = (short) (len - start);
		byte[] subArray = new byte[length];
		for(short i = 0;i < len - start;i++)
		{
			subArray[i] = byteArray[i + start];
		}
		return subArray;
	}

	public SHA256(byte[] msg) {

		for(int i=0;i<64;i++)
			k[i]=hexToBi(K[i]);

		msg_binary= StringToBinary(msg);
		short LENGTH=(short) msg_binary.length;


	if(LENGTH<448)
		repeat_num=1;
	else if(LENGTH>=448&&LENGTH<=512)
		repeat_num=2;
	else {
		if(LENGTH%512<448)
			repeat_num=LENGTH/512+1;
		else
			repeat_num=LENGTH/512+2;
	}

	byte[] cw = new byte[512*repeat_num];

	for(int i=0;i<LENGTH;i++) {//placing bits
		cw[i]= msg_binary[i];
	}

	byte[] str1=toBinaryString(LENGTH,(short)16);

	cw[LENGTH]='1';
	for(short i=(short) (LENGTH+1);i<512*repeat_num-str1.length;i++)
	{
		cw[i]='0';
	}
	for(short i=(short) (512*repeat_num-str1.length);i<512*repeat_num;i++)
	{
		cw[i]= str1[i-512*repeat_num+str1.length];
	}
	str2 = new byte[512*repeat_num];
	for(int i=0;i<512*repeat_num;i++) {
		str2[i] = cw[i];
	}


	for(short n=0;n<repeat_num;n++){
		//w[0] to w[80]
		byte[] str3;//store 512 bits of each group
		str3 = subByteArray(str2, (short)(n*512),(short)((n+1)*512));//get 512 bits from each group

		for(int i=0;i<16;i++)
		{
			w[i]=subByteArray(str3, (short)(i*32), (short)((i+1)*32));
		}

		for(int i=16;i<64;i++)
		{
			w[i]=Add(Add(smallSigmaOne(w[i-2]),w[i-7]),Add(smallSigmaZero(w[i-15]),w[i-16]));
		}
		A = (hexToBi(H0));
		B = (hexToBi(H1));
		C = (hexToBi(H2));
		D = (hexToBi(H3));
		E = (hexToBi(H4));
		F = (hexToBi(H5));
		G = (hexToBi(H6));
		H = (hexToBi(H7));
		SHA_256(A,B,C,D,E,F,G,H);
	}
	}

	public byte[] getHash()
	{
		output = new byte[8*8];
		for(short i = 0;i < 64; i++)
		{
				 if(i < 8) {output[i] = H0[i%8];}
					else if(i < 8) {output[i] = H0[i%8];}
					else if(i < 16) {output[i] = H1[i%8];}
					else if(i < 24) {output[i] = H2[i%8];}
					else if(i < 32) {output[i] = H3[i%8];}
					else if(i < 40) {output[i] = H4[i%8];}
					else if(i < 48) {output[i] = H5[i%8];}
					else if(i < 56) {output[i] = H6[i%8];}
					else /*if(i < 64)*/ {output[i] = H7[i%8];}
		}
		return output;
	}

	//Calculating A,B,C,D,E,F,G,H



	public  byte[] StringToBinary(byte[] str)
	{

		byte[] st=new byte[str.length*8];

		for(short index = 0; index < str.length; index++)
		{
			switch(str[index])
			{
				case 0x30:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x40;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x41;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x40;
					break;
				}
                case 0x31:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x40;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x41;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x32:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x40;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x41;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x41;
                    st[index*8 + 7] = 0x40;
					break;
				}
                case 0x33:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x40;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x41;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x41;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x34:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x40;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x41;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x41;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x40;
					break;
				}
                case 0x35:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x40;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x41;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x41;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x36:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x40;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x41;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x41;
                    st[index*8 + 6] = 0x41;
                    st[index*8 + 7] = 0x40;
					break;
				}
                case 0x37:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x40;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x41;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x41;
                    st[index*8 + 6] = 0x41;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x38:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x40;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x41;

                    st[index*8 + 4] = 0x41;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x40;
					break;
				}
                case 0x39:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x40;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x41;

                    st[index*8 + 4] = 0x41;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x41:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x41;
					st[index*8 + 2] = 0x40;
					st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x42:
                {
                    st[index*8 + 0] = 0x40;
                    st[index*8 + 1] = 0x41;
                    st[index*8 + 2] = 0x40;
                    st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x41;
                    st[index*8 + 7] = 0x40;
                    break;
                }
                case 0x43:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x41;
					st[index*8 + 2] = 0x40;
					st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x41;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x44:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x41;
					st[index*8 + 2] = 0x40;
					st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x41;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x40;
					break;
				}
                case 0x45:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x41;
					st[index*8 + 2] = 0x40;
					st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x41;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x46:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x41;
					st[index*8 + 2] = 0x40;
					st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x41;
                    st[index*8 + 6] = 0x41;
                    st[index*8 + 7] = 0x40;
					break;
				}
                case 0x61:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x41;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x62:
                {
                    st[index*8 + 0] = 0x40;
                    st[index*8 + 1] = 0x41;
                    st[index*8 + 2] = 0x41;
                    st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x41;
                    st[index*8 + 7] = 0x40;
                    break;
                }
                case 0x63:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x41;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x40;
                    st[index*8 + 6] = 0x41;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x64:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x41;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x41;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x40;
					break;
				}
                case 0x65:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x41;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x41;
                    st[index*8 + 6] = 0x40;
                    st[index*8 + 7] = 0x41;
					break;
				}
                case 0x66:
				{
                    st[index*8 + 0] = 0x40;
					st[index*8 + 1] = 0x41;
					st[index*8 + 2] = 0x41;
					st[index*8 + 3] = 0x40;

                    st[index*8 + 4] = 0x40;
                    st[index*8 + 5] = 0x41;
                    st[index*8 + 6] = 0x41;
                    st[index*8 + 7] = 0x40;
					break;
				}


			}
		}
//		for(short i=0;i<str.length;i++)
//		{
//			str2=str2.append(fillZero(Integer.toBinarybyte[](Integer.valueOf(str.charAt(i))),8));
//		}
//		return str2.tobyte[]();
		return st;
	}

	public  byte[] fillZero(byte[] str,int n)
	{
		byte[] str2 = new byte[str.length + n];
		for(short i  = 0; i < str.length; i++)
		{
			str2[i + n] = str[i];
		}
		if(str.length < n)
		{
			for(short i = 0; i < n - str.length; i++)
			{
				str2[i] = 0x30;
			}
		}
		return str2;
	}

	//different OR
	public  byte[] bit_df_or(byte[] str1,byte[] str2)
	{
		byte[] str = new byte[str1.length];
		for(short i=0;i<str1.length;i++) {
			if(str1[i]==str2[i])
				str[i] = 0x30;
			else
				str[i] = 0x31;
		}
		return str;
	}
	//same OR
	public  byte[] bit_sa_or(byte[] str1,byte[] str2)
	{
		byte[] str = new byte[str1.length];
		for(short i=0;i<str1.length;i++)
		{
			if(str1[i]==str2[i])
				str[i] = 0x31;
			else
				str[i] = 0x30;
		}
		return str;
	}
	//AND
	public  byte[] and(byte[] str1,byte[] str2)
	{
		byte[] str = new byte[str1.length];
		for(short i=0;i<str1.length;i++)
		{
			if(str1[i]==0x30||str2[i]==0x30)
				str[i] = 0x30;
			else
				str[i] = 0x31;
		}
		return str;
	}
	//OR
	public  byte[] bit_or(byte[] str1,byte[] str2) {
		byte[] str = new byte[str1.length];
		for(short i=0;i<str1.length;i++)
		{
			if(str1[i]==0x31||str2[i]==0x31)
				str[i] = 0x31;
			else
				str[i] = 0x30;
		}
		return str;
	}
	//NOT
	public  byte[] not(byte[] str1) {
		byte[] str = new byte[str1.length];
		for(short i=0;i<str1.length;i++)
		{
			if(str1[i]==0x30)
				str[i] = 0x31;
			else
				str[i] = 0x30;
		}
		return str;
	}

	public  void SHA_256(byte[] A,byte[] B,byte[] C,byte[] D,byte[] E,byte[] F,byte[] G,byte[] H) {
		byte[] temp1=new byte[A.length];
		byte[] temp2=new byte[A.length];

		for(int i=0;i<64;i++) {
			temp1=T1(H,E,ch(E,F,G),w[i],k[i]);
			temp2=Add(temp1,T2(A,maj(A,B,C)));
			H=G;
			G=F;
			F=E;
			E=Add(D,temp1);
			D=C;
			C=B;
			B=A;
			A=temp2;
		}

		H0=biToHex(Add(A,hexToBi(H0)));
		H1=biToHex(Add(B,hexToBi(H1)));
		H2=biToHex(Add(C,hexToBi(H2)));
		H3=biToHex(Add(D,hexToBi(H3)));
		H4=biToHex(Add(E,hexToBi(H4)));
		H5=biToHex(Add(F,hexToBi(H5)));
		H6=biToHex(Add(G,hexToBi(H6)));
		H7=biToHex(Add(H,hexToBi(H7)));

	}

	//rotate left n bits
	public  byte[] rotl(byte[] str,short n)
	{
		short len = (short)str.length;
		byte[] buffer = new byte[len];
		for(short i = n; i < len; i++)
		{
			buffer[i - n] = str[i];
		}
		for(short i = 0; i < n; i++)
		{
			buffer[len - n + i] = str[i];
		}
		return buffer;
	}
	//rotate right n bits
	public  byte[] rotr(byte[] str,int n)
	{
		short len = (short)str.length;
		byte[] buffer = new byte[len];
		for(short i = (short) n; i < len; i++)
		{
			buffer[i - n] = str[i];
		}
		for(short i = 0; i < n; i++)
		{
			buffer[len - 1 - i] = str[i];
		}
		return buffer;
	}

	//right shift n bits
	public  byte[] shr(byte[] str,int n) {
		byte[] result = new byte[str.length];

		for(short i = 0; i < n;i++)
		{result[i] = 0x30;}
		for(short i = (short) n; i < str.length; i++)
		{
			result[i] = str[i - n];
		}
		return result;
	}

	//ADD
	public  byte[] Add(byte[] str1,byte[] str2)
	{
		byte[] cArray=new byte[32];
		short flag=0;
		for(short i=(short) (str1.length-1);i>=0;i--)
		{
			cArray[i]=(byte)(((str1[i]-'0')+((str2[i]-'0'))+flag)%2+'0');
			if(((str1[i]-'0')+(str2[i]-'0')+flag)>=2)
				flag=1;
			else
				flag=0;
		}
		return cArray;
	}

	public  byte[] ch(byte[] str1,byte[] str2,byte[] str3) {
		return bit_df_or(and(str1,str2),and(not(str1),str3));
	}

	public  byte[] maj(byte[] str1,byte[] str2,byte[] str3) {
		return bit_df_or(bit_df_or(and(str1,str2),and(str1,str3)),and(str2,str3));
	}

	public  byte[] smallSigmaZero(byte[] str1) {
		return bit_df_or(bit_df_or(rotr(str1,7),rotr(str1,18)),shr(str1,3));
	}

	public  byte[] smallSigmaOne(byte[] str1) {
		return bit_df_or(bit_df_or(rotr(str1,17),rotr(str1,19)),shr(str1,10));
	}

	public  byte[] bigSigmaZero(byte[] str1) {
		return bit_df_or(bit_df_or(rotr(str1,2),rotr(str1,13)),rotr(str1,22));
	}

	public  byte[] bigSigmaOne(byte[] str1) {
		return bit_df_or(bit_df_or(rotr(str1,6),rotr(str1,11)),rotr(str1,25));
	}

	public  byte[] biToHex(byte[] str)
	{
		byte temp=0;
		byte[] HexArray = new byte[str.length/4];

		for(short i=0; i< str.length/4; i = (short) (i + 4))
		{
			temp = (byte) ((str[i + 0] - '0')*8 + (str[i + 1] - '0')*4 + (str[i + 2] - '0')*2 + (str[i + 3] - '0')*1);
			HexArray[i] = temp;
		}
		return HexArray;
	}

	public  byte[] hexToBi(byte[] str)
	{

		short strLength = (short)str.length;

		byte[] st = new byte[strLength*4];
		short index = 0;
		for(index = 0; index < strLength; index = (short)(index + 1))
		{
			switch(str[index])
			{
				case 0x30:
				{
					st[index*4 + 0] = 0x40;
					st[index*4 + 1] = 0x40;
					st[index*4 + 2] = 0x40;
					st[index*4 + 3] = 0x40;
					break;
				}
				case 0x31:
				{
					st[index*4 + 0] = 0x40;
					st[index*4 + 1] = 0x40;
					st[index*4 + 2] = 0x40;
					st[index*4 + 3] = 0x41;
					break;
				}
				case 0x32:
				{
					st[index*4 + 0] = 0x40;
					st[index*4 + 1] = 0x40;
					st[index*4 + 2] = 0x41;
					st[index*4 + 3] = 0x40;
					break;
				}
				case 0x33:
				{
					st[index*4 + 0] = 0x40;
					st[index*4 + 1] = 0x40;
					st[index*4 + 2] = 0x41;
					st[index*4 + 3] = 0x41;
					break;
				}
				case 0x34:
				{
					st[index*4 + 0] = 0x40;
					st[index*4 + 1] = 0x41;
					st[index*4 + 2] = 0x40;
					st[index*4 + 3] = 0x40;
					break;
				}
				case 0x35:
				{
					st[index*4 + 0] = 0x40;
					st[index*4 + 1] = 0x41;
					st[index*4 + 2] = 0x40;
					st[index*4 + 3] = 0x41;
					break;
				}
				case 0x36:
				{
					st[index*4 + 0] = 0x40;
					st[index*4 + 1] = 0x41;
					st[index*4 + 2] = 0x41;
					st[index*4 + 3] = 0x40;
					break;
				}
				case 0x37:
				{
					st[index*4 + 0] = 0x40;
					st[index*4 + 1] = 0x41;
					st[index*4 + 2] = 0x41;
					st[index*4 + 3] = 0x41;
					break;
				}
				case 0x38:
				{
					st[index*4 + 0] = 0x41;
					st[index*4 + 1] = 0x40;
					st[index*4 + 2] = 0x40;
					st[index*4 + 3] = 0x40;
					break;
				}
				case 0x39:
				{
					st[index*4 + 0] = 0x41;
					st[index*4 + 1] = 0x40;
					st[index*4 + 2] = 0x40;
					st[index*4 + 3] = 0x41;
					break;
				}
				case 0x41:
				case 0x61:
				{
					st[index*4 + 0] = 0x41;
					st[index*4 + 1] = 0x40;
					st[index*4 + 2] = 0x41;
					st[index*4 + 3] = 0x40;
					break;
				}
				case 0x42:
				case 0x62:
				{
					st[index*4 + 0] = 0x41;
					st[index*4 + 1] = 0x40;
					st[index*4 + 2] = 0x41;
					st[index*4 + 3] = 0x41;
					break;
				}
				case 0x43:
				case 0x63:
				{
					st[index*4 + 0] = 0x41;
					st[index*4 + 1] = 0x41;
					st[index*4 + 2] = 0x40;
					st[index*4 + 3] = 0x40;
					break;
				}
				case 0x44:
				case 0x64:
				{
					st[index*4 + 0] = 0x41;
					st[index*4 + 1] = 0x41;
					st[index*4 + 2] = 0x40;
					st[index*4 + 3] = 0x41;
					break;
				}
				case 0x45:
				case 0x65:
				{
					st[index*4 + 0] = 0x41;
					st[index*4 + 1] = 0x41;
					st[index*4 + 2] = 0x41;
					st[index*4 + 3] = 0x40;
					break;
				}
				case 0x46:
				case 0x66:
				{
					st[index*4 + 0] = 0x41;
					st[index*4 + 1] = 0x41;
					st[index*4 + 2] = 0x41;
					st[index*4 + 3] = 0x41;
					break;
				}
				default:break;
			}
		}
		return st;
	}
	public static byte[] toBinaryString(short i,short SIZE) {
		return toUnsignedString0(i, (short)1,SIZE);
	}

	private static byte[] toUnsignedString0(short val, short shift,short SIZE) {
		// assert shift > 0 && shift <=5 : "Illegal shift value";
		short mag = (short) (SIZE - numberOfLeadingZeros(val));
		short chars = (short) (((mag + (shift - 1)) / shift >= 1 )? ((mag + (shift - 1)) / shift ) : 1);
//		short chars = (short) Math.max(((mag + (shift - 1)) / shift), 1);
		byte[] buf = new byte[chars];

		formatUnsignedshort(val, shift, buf, (short) 0, chars);

		// Use special constructor which takes over "buf".
		return buf;
	}

	public static short numberOfLeadingZeros(short i) {
		// HD, Figure 5-6
		if (i == 0)
			return 16;
		short n = 1;
		if (i >>> 8 == 0) {
			n += 8;
			i <<= 8;
		}
		if (i >>> 12 == 0) {
			n += 4;
			i <<= 4;
		}
		if (i >>> 14 == 0) {
			n += 2;
			i <<= 2;
		}
		n -= i >>> 15;
		return n;
	}

	public static short formatUnsignedshort(short val, short shift, byte[] buf, short offset, short len)
	{
		final byte[] digits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
				'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
		short charPos = len;
		short radix = (short) (1 << shift);
		short mask = (short) (radix - 1);
		do {
			buf[offset + --charPos] = digits[val & mask];
			val >>>= shift;
		} while (val != 0 && charPos > 0);

		return charPos;
	}

	//find T1
	public  byte[] T1(byte[] str_h,byte[] str_e,byte[] str_ch,byte[] str_w,byte[] str_k) {
		return Add(Add(Add(str_h,bigSigmaOne(str_e)),Add(str_ch,str_w)),str_k);
	}
	//find T2
	public  byte[] T2(byte[] str_a,byte[] str_maj) {
		return Add(bigSigmaZero(str_a),str_maj);
	}
	public static void main(String[] args) {
		SHA256 sha256 = new SHA256("a".getBytes());
		byte[] re = sha256.getHash();
		System.out.println(re);
//		for(byte i : re)
//		{
//			System.out.print((char)i);
//		}
	}

}
