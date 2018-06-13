package btc;

import javacard.framework.JCSystem;
import javacard.framework.Util;

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
		for(short i = 0; i < temp.length; i++)//初始化
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
		for(i = 0; i < 64/4; i++)
        { 
        	messageHigh[i]  = (short)((short)(temp[i*4]<<8) + (((short)temp[i*4+1])&0xFF)); 
        	messageLow[i]  = (short)((short)(temp[i*4+2]<<8) + (((short)temp[i*4+3])&0xFF)); 
        }
		deal(messageHigh, messageLow);
	}
	/*
	 * @brief: 处理512比特数据 
	 */
	private static void deal(short[] mHigh,short[] mLow)
	{
		short i;
		short t1High; short t1Low;
		short t2High; short t2Low;
		short[] wHigh = new short[64];
		short[] wLow = new short[64];
		short AHigh; short ALow;
		short BHigh; short BLow;
		short CHigh; short CLow;
		short DHigh; short DLow;
		short EHigh; short ELow;
		short FHigh; short FLow;
		short GHigh; short GLow;
		short HHigh; short HLow;
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
		AHigh = digestHigh[0];
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
		HLow = digestLow[7];  
	    short kHigh, kLow;
	    short addXHigh, addXLow;
	    for(i=0;i<64;i++)
	    {  
	    	kHigh = k[2*i];
	    	kLow = k[2*i+1]; 
			lSigma_1(EHigh, ELow); //b1
			Uint32.add(HHigh, HLow, lSigma1High, lSigma1Low);//b2 = Uint32.add(H, b1); 
			addXHigh = Uint32.addHigh;
			addXLow = Uint32.addLow;
			conditional(EHigh, ELow, FHigh, FLow, GHigh, GLow); //b3
			Uint32.add(condHigh, condLow, kHigh, kLow);//b4 
			Uint32.add(
	        		addXHigh, addXLow, Uint32.addHigh, Uint32.addLow
			);//b5 
	        Uint32.add(  
	        		Uint32.addHigh, Uint32.addLow,
	        		wHigh[i], wLow[i]);//t1
	        t1High = Uint32.addHigh;
	        t1Low = Uint32.addLow; 
	        lSigma_0(AHigh, ALow);//b1 
	        majority(AHigh, ALow, BHigh, BLow, CHigh, CLow);//b2  
	        Uint32.add( lSigma0High, lSigma0Low, majorHigh, majorLow); //t2
	        t2High = Uint32.addHigh;
	        t2Low = Uint32.addLow;
	        HHigh = GHigh; HLow = GLow;//H = G;  
	        GHigh = FHigh; GLow = FLow;//G = F;  
	        FHigh = EHigh ;FLow = ELow;//F = E;   
	        Uint32.add(DHigh, DLow, t1High, t1Low);//E  
	        EHigh = Uint32.addHigh;
	        ELow = Uint32.addLow;
	        DHigh = CHigh; DLow = CLow;//D = C;  
	        CHigh = BHigh; CLow = BLow;//C = B;  
	        BHigh = AHigh; BLow = ALow;//B = A;   
	        Uint32.add(t1High, t1Low, t2High, t2Low);//A
	        AHigh = Uint32.addHigh;
	        ALow = Uint32.addLow;
	    } 
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
	    digestHigh[7] = Uint32.addHigh; digestLow[7] = Uint32.addLow;    
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
