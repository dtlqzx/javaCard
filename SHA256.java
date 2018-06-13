package Blockchain;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import java.*;
public class SHA256 {
 	private static final short[] k = new short[]{
		(short)0x428a,(short)0x2f98,(short)0x7137,(short)0x4491,(short)0xb5c0,(short)0xfbcf,(short)0xe9b5,(short)0xdba5,(short)0x3956,(short)0xc25b,(short)0x59f1,(short)0x11f1,(short)0x923f,(short)0x82a4,(short)0xab1c,(short)0x5ed5,(short)0xd807,(short)0xaa98,(short)0x1283,(short)0x5b01,(short)0x2431,(short)0x85be,(short)0x550c,(short)0x7dc3,(short)0x72be,(short)0x5d74,(short)0x80de,(short)0xb1fe,(short)0x9bdc,(short)0x6a7,(short)0xc19b,(short)0xf174,
		(short)0xe49b,(short)0x69c1,(short)0xefbe,(short)0x4786,(short)0xfc1,(short)0x9dc6,(short)0x240c,(short)0xa1cc,(short)0x2de9,(short)0x2c6f,(short)0x4a74,(short)0x84aa,(short)0x5cb0,(short)0xa9dc,(short)0x76f9,(short)0x88da,(short)0x983e,(short)0x5152,(short)0xa831,(short)0xc66d,(short)0xb003,(short)0x27c8,(short)0xbf59,(short)0x7fc7,(short)0xc6e0,(short)0xbf3,(short)0xd5a7,(short)0x9147,(short)0x6ca,(short)0x6351,(short)0x1429,(short)0x2967,
		(short)0x27b7,(short)0xa85,(short)0x2e1b,(short)0x2138,(short)0x4d2c,(short)0x6dfc,(short)0x5338,(short)0xd13,(short)0x650a,(short)0x7354,(short)0x766a,(short)0xabb,(short)0x81c2,(short)0xc92e,(short)0x9272,(short)0x2c85,(short)0xa2bf,(short)0xe8a1,(short)0xa81a,(short)0x664b,(short)0xc24b,(short)0x8b70,(short)0xc76c,(short)0x51a3,(short)0xd192,(short)0xe819,(short)0xd699,(short)0x624,(short)0xf40e,(short)0x3585,(short)0x106a,(short)0xa070,
		(short)0x19a4,(short)0xc116,(short)0x1e37,(short)0x6c08,(short)0x2748,(short)0x774c,(short)0x34b0,(short)0xbcb5,(short)0x391c,(short)0xcb3,(short)0x4ed8,(short)0xaa4a,(short)0x5b9c,(short)0xca4f,(short)0x682e,(short)0x6ff3,(short)0x748f,(short)0x82ee,(short)0x78a5,(short)0x636f,(short)0x84c8,(short)0x7814,(short)0x8cc7,(short)0x208,(short)0x90be,(short)0xfffa,(short)0xa450,(short)0x6ceb,(short)0xbef9,(short)0xa3f7,(short)0xc671,(short)0x78f2
		};
	private static short[] messageHigh = new short[16];
	private static short[] messageLow = new short[16];
	private static short[] digestHigh = new short[8];
	private static short[] digestLow = new short[8];
	private static final short[] ini = new short[]{ //message 初值
			(short)0x6a09,(short)0xe667,
			(short)0xbb67,(short)0xae85,
			(short)0x3c6e,(short)0xf372,
			(short)0xa54f,(short)0xf53a,
			(short)0x510e,(short)0x527f,
			(short)0x9b05,(short)0x688c,
			(short)0x1f83,(short)0xd9ab,
			(short)0x5be0,(short)0xcd19};
	private static byte[] temp;
	/*
	 * 构造器
	 * @param: Y 报文
	 * @param: length 报文长度
	 * @param: buffer 存放摘要的数组
	 */
	public SHA256(byte[] Y, short length, byte[] buffer, short offset)
	{
		init();
		pad(Y, length);
		getByteDigest(buffer, offset);
	}
	/*
	 * @brief: 初始化
	 * @return: none
	 */
	public static void init()
	{
		for(short i = 0; i < 8; i++)
		{
			digestHigh[i] = ini[i*2];
			digestLow[i] = ini[i*2+1];
		}
		if(temp == null)
			temp = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);

	}
	/*
	 * constructor
	 */
	public SHA256(){}
	/*
	 * @brief:生成摘要
	 * @param: Y 报文
	 * @param: length 报文长度
	 * @param: buffer 存放摘要的数组
	 * @return: none
	 */
	public static void doAll(byte[] Y, short length, byte[] buffer, short offset)
	{
		init();
		pad(Y, length);
		getByteDigest(buffer, offset);
	}
	/*
	 * @brief: 添加填充位和长度并处理报文
	 * @param: Y 报文(数组大小应大于255+64字节)
	 * @param: length 报文长度（字节数）
	 */
	private static void pad(byte[] Y, short length)
	{
		for(short i = 0; i < 64; i++)//初始化
		{
			temp[i] = 0;
		}
		short n = (short)((length+8)/64+1);//报文组数
		//求最后一组报文temp的摘要
		Util.arrayCopyNonAtomic(Y, (short)((n-1)*64), temp, (short)0, (short)(length%64));
		short m = (short)(length%64);//报文长度
		short d = (55 - m)>0? (short)(55-m):(short)(m-55);//填充0x00长度
	    //填充1次1000 0000
        temp[m] = (byte)0x80;
        //填充d次0000 0000
        byte i;
        for(i = (byte)(m+1); i < m+1+d; i++)
        {
        	temp[i] = (byte)0x00;
        }
        //填充长度位数的63-0位
        for(i=1;i <= 2;i++){
            temp[64-i] = (byte)(8*length>>(i-1)*8);
        }
        //byte[]数组转换成short[]数组
		for(i = 0; i < 16; i++)
        {
        	messageHigh[i]  = (short)((short)(temp[i*4]<<8) + (((short)temp[i*4+1])&0xFF));
        	messageLow[i]  = (short)((short)(temp[i*4+2]<<8) + (((short)temp[i*4+3])&0xFF));
        }
		deal(messageHigh, messageLow);
	}
	/*
	 * @brief: 处理512比特数据
	 */
	private static short[] wHigh;
	private static short[] wLow;
	private static short[] A2HHigh;
	private static short[] A2HLow;
	private static void deal(short[] mHigh,short[] mLow)
	{
		short i;
		short t1High; short t1Low;
		short t2High; short t2Low;
		if(wHigh == null)
			wHigh = JCSystem.makeTransientShortArray((short)64, JCSystem.CLEAR_ON_DESELECT);
		if(wLow == null)
			wLow = JCSystem.makeTransientShortArray((short)64, JCSystem.CLEAR_ON_DESELECT);
		if(A2HHigh == null)
			A2HHigh = JCSystem.makeTransientShortArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		if(A2HLow == null)
			A2HLow = JCSystem.makeTransientShortArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		/*short AHigh; short ALow;
		short BHigh; short BLow;
		short CHigh; short CLow;
		short DHigh; short DLow;
		short EHigh; short ELow;
		short FHigh; short FLow;
		short GHigh; short GLow;
		short HHigh; short HLow;*/
		for(i = 0; i<16; i++)
		{
			wHigh[i] = mHigh[i];
			wLow[i] = mLow[i];
		}
		short b1High,b1Low;
		for(i = 16; i < 64; i++)// SSigma_1(W[i-2])+W[i-7]+SSigma_0(W[i-15])+W[i-16];
		{
			//SSigma_1(W[i-2])
			sSigma_1(wHigh[i-2],wLow[i-2]);
			//SSigma_0(W[i-15])
			sSigma_0(wHigh[i-15],wLow[i-15]);
			//SSigma_1(W[i-2])+W[i-7]
			Uint32.add(sSigma1High,sSigma1Low,wHigh[i-7],wLow[i-7]);
			b1High = Uint32.addHigh;
			b1Low = Uint32.addLow;
			//SSigma_0(W[i-15])+W[i-16]
			Uint32.add(sSigma0High, sSigma0Low, wHigh[i-16], wLow[i-16]);
			//SSigma_1(W[i-2])+W[i-7]+SSigma_0(W[i-15])+W[i-16]
			Uint32.add(Uint32.addHigh, Uint32.addLow, b1High, b1Low);
			wHigh[i] = Uint32.addHigh;
			wLow[i] = Uint32.addLow;
		}
		for(i = 0; i < 8; i++)
		{
			A2HHigh[i] = digestHigh[i];
			A2HLow[i] = digestLow[i];
		}
		/*AHigh = digestHigh[0];
		ALow = digestLow[0];
		BHigh = digestHigh[1];
		BLow = digestLow[1];
		CHigh = digestHigh[2];
		CLow = digestLow[2];
		DHigh = digestHigh[3];
		DLow = digestLow[3];
		EHigh = digestHigh[4];
		ELow = digestLow[4];
		FHigh = digestHigh[5];
		FLow = digestLow[5];
		GHigh = digestHigh[6];
		GLow = digestLow[6];
		HHigh = digestHigh[7];
		HLow = digestLow[7];  */
	    short kHigh, kLow;
	    short addXHigh, addXLow;
	    for(i=0;i<64;i++)
	    {
	    	kHigh = k[2*i];
	    	kLow = k[2*i+1];
			lSigma_1(A2HHigh[4], A2HLow[4]); //b1 lSigma_1(E)
			Uint32.add(A2HHigh[7], A2HLow[7], lSigma1High, lSigma1Low);//b2 = Uint32.add(H, b1);
			addXHigh = Uint32.addHigh;
			addXLow = Uint32.addLow;
			conditional(A2HHigh[4], A2HLow[4], A2HHigh[5], A2HLow[5], A2HHigh[6], A2HLow[6]); //b3
			Uint32.add(condHigh, condLow, kHigh, kLow);//b4
			Uint32.add(
	        		addXHigh, addXLow, Uint32.addHigh, Uint32.addLow
			);//b5
	        Uint32.add(
	        		Uint32.addHigh, Uint32.addLow,
	        		wHigh[i], wLow[i]);//t1
	        t1High = Uint32.addHigh;
	        t1Low = Uint32.addLow;
	        lSigma_0(A2HHigh[0], A2HLow[0]);//b1
	        majority(A2HHigh[0], A2HLow[0], A2HHigh[1], A2HLow[1], A2HHigh[2], A2HLow[2]);//b2
	        Uint32.add( lSigma0High, lSigma0Low, majorHigh, majorLow); //t2
	        t2High = Uint32.addHigh;
	        t2Low = Uint32.addLow;
	        short j;
	        for(j =  7; j > 4; j--)
	        {
	        	A2HHigh[j] = A2HHigh[j-1];
	        	A2HLow[j] = A2HLow[j-1];
	        }
	        /*HHigh = GHigh; HLow = GLow;//H = G;
	        GHigh = FHigh; GLow = FLow;//G = F;
	        FHigh = EHigh ;FLow = ELow;//F = E;
*/	        Uint32.add(A2HHigh[3], A2HLow[3], t1High, t1Low);//E
			A2HHigh[4] = Uint32.addHigh;
			A2HLow[4] = Uint32.addLow;
			for(j =  3; j > 0; j--)
	        {
	        	A2HHigh[j] = A2HHigh[j-1];
	        	A2HLow[j] = A2HLow[j-1];
	        }
	        /*DHigh = CHigh; DLow = CLow;//D = C;
	        CHigh = BHigh; CLow = BLow;//C = B;
	        BHigh = AHigh; BLow = ALow;//B = A;   */
			Uint32.add(t1High, t1Low, t2High, t2Low);//A
			A2HHigh[0] = Uint32.addHigh;
			A2HLow[0] = Uint32.addLow;
	    }
	    for(i = 0; i < 8; i++)
	    {
		    Uint32.add(digestHigh[i], digestLow[i], A2HHigh[i], A2HLow[i]);
		    digestHigh[i] = Uint32.addHigh; digestLow[i] = Uint32.addLow;
	    }
	    /*
	     //messageDigest.H[0]=  Uint32.add(messageDigest.H[0], A);
	    Uint32.add(digestHigh[0], digestLow[0], AHigh, ALow);
	    digestHigh[0] = Uint32.addHigh; digestLow[0] = Uint32.addLow;
	    //messageDigest.H[1]=  Uint32.add(messageDigest.H[1], B);
	    Uint32.add(digestHigh[1], digestLow[1], BHigh, BLow);
	    digestHigh[1] = Uint32.addHigh; digestLow[1] = Uint32.addLow;
	    //messageDigest.H[2]=  Uint32.add(messageDigest.H[2], C);
	    Uint32.add(digestHigh[2], digestLow[2], CHigh, CLow);
	    digestHigh[2] = Uint32.addHigh; digestLow[2] = Uint32.addLow;
	    //messageDigest.H[3]=  Uint32.add(messageDigest.H[3], D);
	    Uint32.add(digestHigh[3], digestLow[3], DHigh, DLow);
	    digestHigh[3] = Uint32.addHigh; digestLow[3] = Uint32.addLow;
	    //messageDigest.H[4]=  Uint32.add(messageDigest.H[4], E);
	    Uint32.add(digestHigh[4], digestLow[4], EHigh, ELow);
	    digestHigh[4] = Uint32.addHigh; digestLow[4] = Uint32.addLow;
	    //messageDigest.H[5]=  Uint32.add(messageDigest.H[5], F);
	    Uint32.add(digestHigh[5], digestLow[5], FHigh, FLow);
	    digestHigh[5] = Uint32.addHigh; digestLow[5] = Uint32.addLow;
	    //messageDigest.H[6]=  Uint32.add(messageDigest.H[6], G);
	    Uint32.add(digestHigh[6], digestLow[6], GHigh, GLow);
	    digestHigh[6] = Uint32.addHigh; digestLow[6] = Uint32.addLow;
	    //messageDigest.H[7]=  Uint32.add(messageDigest.H[7], H);
	    Uint32.add(digestHigh[7], digestLow[7], HHigh, HLow);
	    digestHigh[7] = Uint32.addHigh; digestLow[7] = Uint32.addLow;  */
	}
	/*
	 * conditional 运算结果变量
	 */
	private static short condHigh;
	private static short condLow;
	//六个逻辑函数
	private static void conditional(short xHigh, short xLow, short yHigh, short yLow, short zHigh, short zLow)//Conditional(x,y,z) ((x&y)^((~x)&z))
	{
		short andXYHigh,andXYLow;
		//x&y
		Uint32.and(xHigh, xLow, yHigh, yLow);
		andXYHigh = Uint32.andHigh;
		andXYLow = Uint32.andLow;
		//~x
		Uint32.not(xHigh, xLow);
		//~x & z
		Uint32.and(Uint32.notHigh,Uint32.notLow,zHigh,zLow);
		//cond x,y,z
		Uint32.xor(andXYHigh, andXYLow, Uint32.andHigh, Uint32.andLow);
		condHigh = Uint32.xorHigh;
		condLow = Uint32.xorLow;
	}
	/*
	 * major 运算结果变量
	 */
	private static short majorHigh;
	private static short majorLow;
	private static void majority(short xHigh, short xLow, short yHigh, short yLow, short zHigh, short zLow) //Majority(x,y,z) ((x&y)^(x&z)^(y&z))
	{
		short andXYHigh, andXYLow, andXZHigh, andXZLow;
		//x & y
		Uint32.and(xHigh, xLow, yHigh, yLow);
		andXYHigh = Uint32.andHigh;
		andXYLow = Uint32.andLow;
		//x & z
		Uint32.and(xHigh, xLow, zHigh, zLow);
		andXZHigh = Uint32.andHigh;
		andXZLow = Uint32.andLow;
		// (x&y)^(x&z)
		Uint32.xor(andXYHigh, andXYLow, andXZHigh, andXZLow);
		// y & z
		Uint32.and(yHigh, yLow, zHigh, zLow);
		//(x&y)^(x&z)^(y&z)
		Uint32.xor(Uint32.xorHigh, Uint32.xorLow, Uint32.andHigh, Uint32.andLow);
		majorHigh = Uint32.xorHigh;
		majorLow = Uint32.xorLow;
	}
	/*
	 * lSigma_0 运算结果变量
	 */
	private static short lSigma0High;
	private static short lSigma0Low;
	private static void lSigma_0(short xHigh, short xLow)//LSigma_0(x) (ROTL(x,30)^ROTL(x,19)^ROTL(x,10))
	{
		short rotlXHigh, rotlXLow;
		//(ROTL(x,30)
		Uint32.rotl(xHigh, xLow, (short)30);
		rotlXHigh = Uint32.rotlHigh;
		rotlXLow = Uint32.rotlLow;
		//ROTL(x,19)
		Uint32.rotl(xHigh, xLow, (short)19);
		//(ROTL(x,30)^ROTL(x,19)
		Uint32.xor(rotlXHigh, rotlXLow, Uint32.rotlHigh, Uint32.rotlLow);
		//ROTL(x,10))
		Uint32.rotl(xHigh, xLow, (short)10);
		Uint32.xor(
				Uint32.xorHigh, Uint32.xorLow,
				Uint32.rotlHigh,Uint32.rotlLow
				);
		lSigma0High = Uint32.xorHigh;
		lSigma0Low = Uint32.xorLow;
	}
	/*
	 * lSigma_1 运算结果变量
	 */
	private static short lSigma1High;
	private static short lSigma1Low;
	private static void lSigma_1(short xHigh, short xLow) //LSigma_1(x) (ROTL(x,26)^ROTL(x,21)^ROTL(x,7))
	{
		short rotlXHigh, rotlXLow;
		//(ROTL(x,26)
		Uint32.rotl(xHigh, xLow, (short)26);
		rotlXHigh = Uint32.rotlHigh;
		rotlXLow = Uint32.rotlLow;
		//ROTL(x,19)
		Uint32.rotl(xHigh, xLow, (short)21);
		//(ROTL(x,26)^ROTL(x,21)
		Uint32.xor(rotlXHigh, rotlXLow, Uint32.rotlHigh, Uint32.rotlLow);
		//ROTL(x,7))
		Uint32.rotl(xHigh, xLow, (short)7);
		//LSigma_1
		Uint32.xor(
				Uint32.xorHigh, Uint32.xorLow,
				Uint32.rotlHigh,Uint32.rotlLow
				);
		lSigma1High = Uint32.xorHigh;
		lSigma1Low = Uint32.xorLow;
	}
	/*
	 * sSigma_0 运算结果变量
	 */
	private static short sSigma0High;
	private static short sSigma0Low;
	private static void sSigma_0(short xHigh, short xLow)//SSigma_0(x) (ROTL(x,25)^ROTL(x,14)^SHR(x,3))
	{
		short rotlXHigh, rotlXLow;
		//(ROTL(x,25)
		Uint32.rotl(xHigh, xLow, (short)25);
		rotlXHigh = Uint32.rotlHigh;
		rotlXLow = Uint32.rotlLow;
		//ROTL(x,14)
		Uint32.rotl(xHigh, xLow, (short)14);
		//(ROTL(x,25)^ROTL(x,14)
		Uint32.xor(rotlXHigh, rotlXLow, Uint32.rotlHigh, Uint32.rotlLow);
		//SHR(x,3)
		Uint32.shr(xHigh, xLow, (short)3);
		//sSigma_0
		Uint32.xor(
				Uint32.xorHigh, Uint32.xorLow,
				Uint32.shrHigh,Uint32.shrLow
				);
		sSigma0High = Uint32.xorHigh;
		sSigma0Low = Uint32.xorLow;
	}
	/*
	 * sSigma_1 运算结果变量
	 */
	private static short sSigma1High;
	private static short sSigma1Low;
	private static void sSigma_1(short xHigh, short xLow)//SSigma_1(x) (ROTL(x,15)^ROTL(x,13)^SHR(x,10))
	{
		short rotlXHigh, rotlXLow;
		//(ROTL(x,15)
		Uint32.rotl(xHigh, xLow, (short)15);
		rotlXHigh = Uint32.rotlHigh;
		rotlXLow = Uint32.rotlLow;
		//ROTL(x,13)
		Uint32.rotl(xHigh, xLow, (short)13);
		//(ROTL(x,25)^ROTL(x,14)
		Uint32.xor(rotlXHigh, rotlXLow, Uint32.rotlHigh, Uint32.rotlLow);
		//SHR(x,10)
		Uint32.shr(xHigh, xLow, (short)10);
		//sSigma_1
		Uint32.xor(
				Uint32.xorHigh, Uint32.xorLow,
				Uint32.shrHigh,Uint32.shrLow
				);
		sSigma1High = Uint32.xorHigh;
		sSigma1Low = Uint32.xorLow;
	}
	/*
	 * @brief:将MessageDigest存放在byte数组中
	 * @param: buffer 存放摘要的数组
	 * @param: offset 存放摘要的起始位置
	 */
	public static void getByteDigest(byte[] buffer, short offset)
	{
		short i;
		for(i = 0; i < 8; i++)
		{
			buffer[offset + 4*i] = (byte)(digestHigh[i]>>8);
			buffer[offset + 4*i+1] = (byte)(digestHigh[i]&0xFF);
			buffer[offset + 4*i+2] = (byte)(digestLow[i]>>8);
			buffer[offset + 4*i+3] = (byte)(digestLow[i]&0xFF);
		}
	}
}


/*package BTC;

import javacard.framework.JCSystem;
import javacard.framework.Util;
public class SHA256 {
	 final static short NUMBER=(short)32;
	 short repeat_num=1;//groups
	 byte[] msg_binary;
	 byte[] str2;

	 byte[] H0={'6','a','0','9','e','6','6','7'};
	 byte[] H1={'b','b','6','7','a','e','8','5'};
	 byte[] H2={'3','c','6','e','f','3','7','2'};//"3c6ef372".getBytes();
	 byte[] H3={'a','5','4','f','f','5','3','a'};//"a54ff53a".getBytes();
	 byte[] H4={'5','1','0','e','5','2','7','f'};//"510e527f".getBytes();
	 byte[] H5={'9','b','0','5','6','8','8','c'};//"9b05688c".getBytes();
	 byte[] H6={'1','f','8','3','d','9','a','b'};//"1f83d9ab".getBytes();
	 byte[] H7={'5','b','e','0','c','d','1','9'};//"5be0cd19".getBytes();
	 byte[] A,B,C,D,E,F,G,H=new byte[NUMBER];

	 byte[] output;
	 short begin;
	 short end;
	 byte[]k=new byte[64*32];
	 byte[]temp_k =new byte[NUMBER];
	 byte[]temp_w =new byte[NUMBER];
	 byte[]temp_w1 =new byte[NUMBER];
	 byte[]temp_w2 =new byte[NUMBER];
	 byte[]temp_K =new byte[8];
	 /*byte[]K=
	   {{'4','2','8','a','2','f','9','8'},{'7','1','3','7','4','4','9','1'},{'b','5','c','0','f','b','c','f'},{'e','9','b','5','d','b','a','5'},{'3','9','5','6','c','2','5','b'},{'5','9','f','1','1','1','f','1'},{'9','2','3','f','8','2','a','4'},{'a','b','1','c','5','e','d','5'},
		{'d','8','0','7','a','a','9','8'},{'1','2','8','3','5','b','0','1'},{'2','4','3','1','8','5','b','e'},{'5','5','0','c','7','d','c','3'},{'7','2','b','e','5','d','7','4'},{'8','0','d','e','b','1','f','e'},{'9','b','d','c','0','6','a','7'},{'c','1','9','b','f','1','7','4'},
		{'e','4','9','b','6','9','c','1'},{'e','f','b','e','4','7','8','6'},{'0','f','c','1','9','d','c','6'},{'2','4','0','c','a','1','c','c'},{'2','d','e','9','2','c','6','f'},{'4','a','7','4','8','4','a','a'},{'5','c','b','0','a','9','d','c'},{'7','6','f','9','8','8','d','a'},
		{'9','8','3','e','5','1','5','2'},{'a','8','3','1','c','6','6','d'},{'b','0','0','3','2','7','c','8'},{'b','f','5','9','7','f','c','7'},{'c','6','e','0','0','b','f','3'},{'d','5','a','7','9','1','4','7'},{'0','6','c','a','6','3','5','1'},{'1','4','2','9','2','9','6','7'},
		{'2','7','b','7','0','a','8','5'},{'2','e','1','b','2','1','3','8'},{'4','d','2','c','6','d','f','c'},{'5','3','3','8','0','d','1','3'},{'6','5','0','a','7','3','5','4'},{'7','6','6','a','0','a','b','b'},{'8','1','c','2','c','9','2','e'},{'9','2','7','2','2','c','8','5'},
		{'a','2','b','f','e','8','a','1'},{'a','8','1','a','6','6','4','b'},{'c','2','4','b','8','b','7','0'},{'c','7','6','c','5','1','a','3'},{'d','1','9','2','e','8','1','9'},{'d','6','9','9','0','6','2','4'},{'f','4','0','e','3','5','8','5'},{'1','0','6','a','a','0','7','0'},
		{'1','9','a','4','c','1','1','6'},{'1','e','3','7','6','c','0','8'},{'2','7','4','8','7','7','4','c'},{'3','4','b','0','b','c','b','5'},{'3','9','1','c','0','c','b','3'},{'4','e','d','8','a','a','4','a'},{'5','b','9','c','c','a','4','f'},{'6','8','2','e','6','f','f','3'},
		{'7','4','8','f','8','2','e','e'},{'7','8','a','5','6','3','6','f'},{'8','4','c','8','7','8','1','4'},{'8','c','c','7','0','2','0','8'},{'9','0','b','e','f','f','f','a'},{'a','4','5','0','6','c','e','b'},{'b','e','f','9','a','3','f','7'},{'c','6','7','1','7','8','f','2'}};
*/
	 /*byte[]K=
	   {'4','2','8','a','2','f','9','8','7','1','3','7','4','4','9','1','b','5','c','0','f','b','c','f','e','9','b','5','d','b','a','5','3','9','5','6','c','2','5','b','5','9','f','1','1','1','f','1','9','2','3','f','8','2','a','4','a','b','1','c','5','e','d','5',
		'd','8','0','7','a','a','9','8','1','2','8','3','5','b','0','1','2','4','3','1','8','5','b','e','5','5','0','c','7','d','c','3','7','2','b','e','5','d','7','4','8','0','d','e','b','1','f','e','9','b','d','c','0','6','a','7','c','1','9','b','f','1','7','4',
		'e','4','9','b','6','9','c','1','e','f','b','e','4','7','8','6','0','f','c','1','9','d','c','6','2','4','0','c','a','1','c','c','2','d','e','9','2','c','6','f','4','a','7','4','8','4','a','a','5','c','b','0','a','9','d','c','7','6','f','9','8','8','d','a',
		'9','8','3','e','5','1','5','2','a','8','3','1','c','6','6','d','b','0','0','3','2','7','c','8','b','f','5','9','7','f','c','7','c','6','e','0','0','b','f','3','d','5','a','7','9','1','4','7','0','6','c','a','6','3','5','1','1','4','2','9','2','9','6','7',
		'2','7','b','7','0','a','8','5','2','e','1','b','2','1','3','8','4','d','2','c','6','d','f','c','5','3','3','8','0','d','1','3','6','5','0','a','7','3','5','4','7','6','6','a','0','a','b','b','8','1','c','2','c','9','2','e','9','2','7','2','2','c','8','5',
		'a','2','b','f','e','8','a','1','a','8','1','a','6','6','4','b','c','2','4','b','8','b','7','0','c','7','6','c','5','1','a','3','d','1','9','2','e','8','1','9','d','6','9','9','0','6','2','4','f','4','0','e','3','5','8','5','1','0','6','a','a','0','7','0',
		'1','9','a','4','c','1','1','6','1','e','3','7','6','c','0','8','2','7','4','8','7','7','4','c','3','4','b','0','b','c','b','5','3','9','1','c','0','c','b','3','4','e','d','8','a','a','4','a','5','b','9','c','c','a','4','f','6','8','2','e','6','f','f','3',
		'7','4','8','f','8','2','e','e','7','8','a','5','6','3','6','f','8','4','c','8','7','8','1','4','8','c','c','7','0','2','0','8','9','0','b','e','f','f','f','a','a','4','5','0','6','c','e','b','b','e','f','9','a','3','f','7','c','6','7','1','7','8','f','2'};

	 byte[] w=new byte[64*32];

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

	/*public SHA256(byte[] msg) {

		for(short i=0;i<64;i++){
			Util.arrayCopy(K, i, temp_K, (short)0, (short)8);
			Util.arrayCopy(hexToBi(temp_K),(short)0,k,(short)(i*64),(short)64);
		}
		msg_binary= StringToBinary(msg);
		short LENGTH=(short) msg_binary.length;


	if(LENGTH<448)
		repeat_num=1;
	else if(LENGTH>=448&&LENGTH<=512)
		repeat_num=2;
	else {
		if((LENGTH&0xFF)<(short)448)
			repeat_num=(short)((LENGTH>>8)+1);
		else
			repeat_num=(short)((LENGTH>>8)+2);
	}

	byte[] cw = new byte[512*repeat_num];
	for(short i=0;i<LENGTH;i++) {//placing bits
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
	for(short i=0;i<512*repeat_num;i++) {
		str2[i] = cw[i];
	}


	for(short n=0;n<repeat_num;n++){
		//w[0] to w[80]
		byte[] str3;//store 512 bits of each group
		str3 = subByteArray(str2, (short)(n*512),(short)((n+1)*512));//get 512 bits from each group

		for(short i=0;i<16;i++)
		{
			temp_w=subByteArray(str3, (short)(i*32), (short)((i+1)*32));
			Util.arrayCopy(temp_w, (short)0, w, (short)(i*64), (short)64);
		}

		for(short i=16;i<64;i++)
		{
			Util.arrayCopy(w, (short)0, temp_w, (short)((i-2)*64), (short)64);
			Util.arrayCopy(w, (short)0, temp_w1, (short)((i-2)*64), (short)64);
			temp_w1=Add(smallSigmaOne(temp_w),temp_w1);
			Util.arrayCopy(w, (short)0, temp_w, (short)((i-15)*64), (short)64);
			Util.arrayCopy(w, (short)0, temp_w2, (short)((i-16)*64), (short)64);
			temp_w2=Add(smallSigmaOne(temp_w),temp_w2);
			temp_w=Add(temp_w1,temp_w2);
			//temp_w=Add(Add(smallSigmaOne(w[i-2]),w[i-7]),Add(smallSigmaZero(w[i-15]),w[i-16]));
			Util.arrayCopy(temp_w, (short)0, w, (short)(i*64), (short)64);
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
*/
	/*public byte[] getHash(byte[] msg)
	{
		for(short i=0;i<64;i++){
			Util.arrayCopy(K, i, temp_K, (short)0, (short)8);
			byte[] a=hexToBi(temp_K);
			Util.arrayCopy(a,(short)0,k,(short)(i*NUMBER),(short)NUMBER);
		}
		msg_binary= StringToBinary(msg);
		short LENGTH=(short) msg_binary.length;


	if(LENGTH<448)
		repeat_num=1;
	else if(LENGTH>=448&&LENGTH<=512)
		repeat_num=2;
	else {
		if((LENGTH&0xFF)<(short)448)
			repeat_num=(short)((LENGTH>>8)+1);
		else
			repeat_num=(short)((LENGTH>>8)+2);
	}

	byte[] cw = new byte[512*repeat_num];
	for(short i=0;i<LENGTH;i++) {//placing bits
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
	for(short i=0;i<512*repeat_num;i++) {
		str2[i] = cw[i];
	}


	for(short n=0;n<repeat_num;n++){
		//w[0] to w[80]
		byte[] str3;//store 512 bits of each group
		str3 = subByteArray(str2, (short)(n*512),(short)((n+1)*512));//get 512 bits from each group

		for(short i=0;i<16;i++)
		{
			temp_w=subByteArray(str3, (short)(i*NUMBER), (short)((i+1)*NUMBER));
			Util.arrayCopy(temp_w, (short)0, w, (short)(i*NUMBER), (short)NUMBER);
		}

		for(short i=16;i<64;i++)
		{
			Util.arrayCopy(w, (short)((i-2)*NUMBER), temp_w, (short)0, (short)NUMBER);
			Util.arrayCopy(w, (short)((i-7)*NUMBER), temp_w1, (short)0, (short)NUMBER);
			temp_w1=Add(smallSigmaOne(temp_w),temp_w1);
			Util.arrayCopy(w, (short)((i-15)*NUMBER), temp_w, (short)0, (short)NUMBER);
			Util.arrayCopy(w, (short)((i-16)*NUMBER), temp_w2, (short)0, (short)NUMBER);
			temp_w2=Add(smallSigmaOne(temp_w),temp_w2);
			temp_w=Add(temp_w1,temp_w2);
			//temp_w=Add(Add(smallSigmaOne(w[i-2]),w[i-7]),Add(smallSigmaZero(w[i-15]),w[i-16]));
			Util.arrayCopy(temp_w, (short)0, w, (short)(i*NUMBER), (short)NUMBER);
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
		output = new byte[8*8];
		for(short i = 0;i < 64; i++)
		{
				 if(i < 8) {output[i] = H0[i&0xF];}
					else if(i < 8)  {output[i] = H0[i&0xF];}
					else if(i < 16) {output[i] = H1[i&0xF];}
					else if(i < 24) {output[i] = H2[i&0xF];}
					else if(i < 32) {output[i] = H3[i&0xF];}
					else if(i < 40) {output[i] = H4[i&0xF];}
					else if(i < 48) {output[i] = H5[i&0xF];}
					else if(i < 56) {output[i] = H6[i&0xF];}
					else {output[i] = H7[i&0xF];}
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

	public  byte[] fillZero(byte[] str,short n)
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
		byte[] temp1=JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
		byte[] temp2=JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
		for(short i=0;i<64;i++) {
			Util.arrayCopy(k, (short)(i*NUMBER), temp_k, (short)0, (short)NUMBER);
			Util.arrayCopy(w, (short)(i*NUMBER), temp_w, (short)0, (short)NUMBER);
			temp1=T1(H,E,ch(E,F,G),temp_w,temp_k);
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
	public  byte[] rotr(byte[] str,short n)
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
	public  byte[] shr(byte[] str,short n) {
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
		byte[] cArray=str1;//=new byte[NUMBER];
		short flag=0;
		for(short i=NUMBER-1;i>=0;i--)
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
		return bit_df_or(bit_df_or(rotr(str1,(short)7),rotr(str1,(short)18)),shr(str1,(short)3));
	}

	public  byte[] smallSigmaOne(byte[] str1) {
		return bit_df_or(bit_df_or(rotr(str1,(short)17),rotr(str1,(short)19)),shr(str1,(short)10));
	}

	public  byte[] bigSigmaZero(byte[] str1) {
		return bit_df_or(bit_df_or(rotr(str1,(short)2),rotr(str1,(short)13)),rotr(str1,(short)22));
	}

	public  byte[] bigSigmaOne(byte[] str1) {
		return bit_df_or(bit_df_or(rotr(str1,(short)6),rotr(str1,(short)11)),rotr(str1,(short)25));
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

		//short strLength = (short)str.length;

		byte[] st = new byte[NUMBER];
		short index = 0;
		for(index = 0; index < 8; index++)
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
}*/
