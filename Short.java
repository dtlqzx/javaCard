package Blockchain;

public class Short 
{
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
}
