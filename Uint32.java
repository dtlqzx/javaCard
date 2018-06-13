package Blockchain;
/*
 * 无符号整型数
 * 由2个short型数构成
 */
public class Uint32 {
	public short uint32_h;//高16位
	public short uint32_l;//低16位
	/*
	 * 加法运算变量
	 */
	public static short addHigh;
	public static short addLow;
	/*
	 * 按位与运算变量
	 */
	public static short andHigh;
	public static short andLow;
	/*
	 * 按位异或运算变量
	 */
	public static short xorHigh;
	public static short xorLow;
	/*
	 * 按位取反运算变量
	 */
	public static short notHigh;
	public static short notLow;
	/*
	 * 循环右移运算变量
	 */
	public static short rotrHigh;
	public static short rotrLow;
	/*
	 * 循环左移运算变量
	 */
	public static short rotlHigh;
	public static short rotlLow;
	/*
	 * 逻辑右移运算变量
	 */
	public static short shrHigh;
	public static short shrLow;
	/*
	 * 构造器
	 */
	public Uint32(short uint32_h, short uint32_l)
	{

		this.uint32_h = uint32_h;
		this.uint32_l = uint32_l;
	}
	/*
	 * 默认构造器
	 */
	public Uint32()
	{
		uint32_h = 0;
		uint32_l = 0;
	}
	/*
	 * @brief: 32位无符号数按位与运算
	 */
	public static void and(short xHigh, short xLow, short yHigh, short yLow)
	{
		andHigh = (short)(xHigh & yHigh);
		andLow = (short)(xLow & yLow);
	}
	/*
	 * @brief: 32位无符号数按位异或运算
	 */
	public static void xor(short xHigh, short xLow, short yHigh, short yLow)
	{
		xorHigh = (short)(xHigh ^ yHigh);
		xorLow = (short)(xLow ^ yLow);
	}
	/*
	 * @brief: 32位无符号数按位取反运算
	 */
	public static void not(short xHigh, short xLow)
	{
		notHigh = (short)(~xHigh);
		notLow = (short)(~xLow);
	}
	/*
	 * @brief: 32位无符号数循环右移
	 * @param: x 操作数
	 * @param: n 移动位数
	 */
	public static void rotr(short xHigh, short xLow, short n)
	{
		n = (short)(n%32);
		short short_h = xHigh;
		short short_l = xLow;
		if(n>16)
		{
			short_h = xLow;
			short_l = xHigh;
			n-=16;
		}
		//short型逻辑右移需做处理，否则符号位会保持
		//(short)short_h)>>n
		short buff = short_h;
		if(n >= 1)
		{
			buff >>= 1;
			buff &= (short)(~0x8000);
			buff >>= (n-1);
		}
		rotrHigh = (short)(
				 (buff) | 	//高16位
				 (short)(short_l<<(16-n)) //低16位
				 );
		//(short)short_l)>>n
		buff = short_l;
		if(n >= 1)
		{
			buff >>= 1;
			buff &= (short)(~0x8000);
			buff >>= (n-1);

		}
		rotrLow = (short)(
				 (((short)short_h)<<(16-n)) | 	//高16位
				 (buff) //低16位
				 );

	}
	/*
	 * @brief: 32位无符号数循环左移
	 * @param: x 操作数
	 * @param: n 移动位数
	 */
	public static void rotl(short xHigh, short xLow, short n)
	{
		n = (short)(n%32);
		short short_h = xHigh;
		short short_l = xLow;
		if(n>16)
		{
			short_h = xLow;
			short_l = xHigh;
			n-=16;
		}
		//short型逻辑右移需做处理，否则符号位会保持
		//(((short)short_l)>>(16-n)
		short buff = short_l;
		if(16-n >= 1)
		{
			buff >>= 1;
			buff &= (short)(~0x8000);
			buff >>=15-n;
		}
		rotlHigh = (short)(
				 (((short)short_h)<<n) | 	//高16位
				 (buff) //低16位
				 );
		//(((short)short_h)>>(16-n)
		buff = short_h;
		if(16-n >= 1)
		{
			buff >>= 1;
			buff &= (short)(~0x8000);
			buff >>=15-n;
		}
		rotlLow = (short)(
				 (buff) | 	//高16位
				 (((short)short_l)<<n) //低16位
				 );
	}
	/*
	 * @brief: 32位无符号数逻辑右移
	 * @param: x 操作数
	 * @param: n 移动位数
	 * @return: 32位无符号数
	 */
	public static void shr(short xHigh, short xLow, short n)
	{
		short short_h = xHigh;
		short short_l = xLow;
		short buff = short_h;
		if(n>16)
		{
			n-=16;
			xHigh = 0;
			//short_h>>n
			if(n >= 1)
			{
				buff >>= 1;
				buff &= (short)(~0x8000);
				buff >>= (n-1);
			}
			xLow = buff;
		}
		else
		{
			//short_h>>n
			buff = short_h;
			if(n >= 1)
			{
				buff >>= 1;
				buff &= (short)(~0x8000);
				buff >>= (n-1);
			}
			xHigh = buff;
			//short_l >> n
			buff = short_l;
			if(n >= 1)
			{
				buff >>= 1;
				buff &= (short)(~0x8000);
				buff >>= (n-1);
			}
			xLow = (short)(short_h<<(16-n)|buff);
		}
		shrHigh = xHigh;
		shrLow = xLow;
	}
	/*
	 * @brief: 32位无符号数加法
	 * @return:32位无符号数
	 */
	public static void add(short xHigh, short xLow, short yHigh, short yLow)
	{
		short addX,addY,addCarry;
		addX = xLow;
		addY = yLow;
		addHigh = yHigh;
		addLow = (short)(addX + addY);
		addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1);
		addHigh += addCarry;
		addHigh += xHigh;
	}

}
