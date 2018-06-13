package btc;

/*
 * �޷���������
 * ��2��short��������
 */
public class Uint32 {
	public short uint32_h;//��16λ
	public short uint32_l;//��16λ
	/*
	 * �ӷ��������
	 */
	public static short addHigh;
	public static short addLow; 
	/*
	 * ��λ���������
	 */
	public static short andHigh;
	public static short andLow;
	/*
	 * ��λ����������
	 */
	public static short xorHigh;
	public static short xorLow;
	/*
	 * ��λȡ���������
	 */
	public static short notHigh;
	public static short notLow;
	/*
	 * ѭ�������������
	 */
	public static short rotrHigh;
	public static short rotrLow;
	/*
	 * ѭ�������������
	 */
	public static short rotlHigh;
	public static short rotlLow;
	/*
	 * �߼������������
	 */
	public static short shrHigh;
	public static short shrLow;
	/*
	 * ������
	 */
	public Uint32(short uint32_h, short uint32_l)
	{
		
		this.uint32_h = uint32_h;
		this.uint32_l = uint32_l;
	}
	/*
	 * Ĭ�Ϲ�����
	 */
	public Uint32()
	{ 
		uint32_h = 0;
		uint32_l = 0;
	}
	/*
	 * @brief: 32λ�޷�������λ������ 
	 */
	public static void and(short xHigh, short xLow, short yHigh, short yLow)
	{
		andHigh = (short)(xHigh & yHigh);
		andLow = (short)(xLow & yLow); 
	}
	/*
	 * @brief: 32λ�޷�������λ������� 
	 */
	public static void xor(short xHigh, short xLow, short yHigh, short yLow)
	{ 
		xorHigh = (short)(xHigh ^ yHigh);
		xorLow = (short)(xLow ^ yLow);
	}
	/*
	 * @brief: 32λ�޷�������λȡ������ 
	 */
	public static void not(short xHigh, short xLow)
	{ 
		notHigh = (short)(~xHigh);
		notLow = (short)(~xLow); 
	}
	/*
	 * @brief: 32λ�޷�����ѭ������
	 * @param: x ������
	 * @param: n �ƶ�λ�� 
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
		//short���߼��������������������λ�ᱣ��
		//(short)short_h)>>n  
		short buff = short_h;
		if(n >= 1)
		{
			buff >>= 1;
			buff &= (short)(~0x8000);
			buff >>= (n-1);
		}
		rotrHigh = (short)(
				 (buff) | 	//��16λ
				 (short)(short_l<<(16-n)) //��16λ
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
				 (((short)short_h)<<(16-n)) | 	//��16λ
				 (buff) //��16λ
				 ); 
  
	}
	/*
	 * @brief: 32λ�޷�����ѭ������
	 * @param: x ������
	 * @param: n �ƶ�λ�� 
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
		//short���߼��������������������λ�ᱣ��
		//(((short)short_l)>>(16-n)
		short buff = short_l;
		if(16-n >= 1)
		{
			buff >>= 1;
			buff &= (short)(~0x8000);
			buff >>=15-n;
		}
		rotlHigh = (short)(
				 (((short)short_h)<<n) | 	//��16λ
				 (buff) //��16λ
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
				 (buff) | 	//��16λ
				 (((short)short_l)<<n) //��16λ
				 );   
	}
	/*
	 * @brief: 32λ�޷������߼�����
	 * @param: x ������
	 * @param: n �ƶ�λ��
	 * @return: 32λ�޷�����
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
	 * @brief: 32λ�޷������ӷ�
	 * @return:32λ�޷�����
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
