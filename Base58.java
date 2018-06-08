package Blockchain;
import javacard.framework.Util;

/**
 * Created with IntelliJ IDEA.
 * User: noah
 * Date: 8/2/13
 * Time: 10:36 AM
 * To change this template use File | Settings | File Templates.
 */
public class Base58 {

//    public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
	public static final byte[] ALPHABET = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x4a,0x4b,0x4c,0x4d,0x4e,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a};
    private static final short[] INDEXES = new short[128];

    public Base58()
    {
		// TODO Auto-generated constructor stub
    	   for (short i = 0; i < INDEXES.length; i++) {
               INDEXES[i] = -1;
           }
//           for (int i = 0; i < ALPHABET.length; i++) {
//               INDEXES[ALPHABET[i]] = i;
//           }

	}

    /**
     * Encodes the given bytes in base58. No checksum is appended.
     */
    public static byte[] encode(byte[] input) {
 	   for (short i = 0; i < INDEXES.length; i++) {
           INDEXES[i] = -1;
       }

    	if (input.length == 0) {
            return null;
        }
        input = copyOfRange(input, (short)0, (short)(input.length));
        // Count leading zeroes.
        short zeroCount = 0;
        while (zeroCount < input.length && input[zeroCount] == 0) {
            ++zeroCount;
        }
        // The actual encoding.
        byte[] temp = new byte[input.length * 2];
        short j = (short)temp.length;

        short startAt = zeroCount;
        while (startAt < input.length) {
            byte mod = divmod58(input, startAt);
            if (input[startAt] == 0) {
                ++startAt;
            }
            temp[--j] = (byte) ALPHABET[mod];
        }

        // Strip extra '1' if there are some after decoding.
        while (j < temp.length && temp[j] == ALPHABET[0]) {
            ++j;
        }
        // Add as many leading '1' as there were leading zeros.
        while (--zeroCount >= 0) {
            temp[--j] = (byte) ALPHABET[0];
        }

        byte[] output = copyOfRange(temp, j, (short)temp.length);
        return output;
//        try {
//            return new String(output, "US-ASCII");
//        } catch (UnsupportedEncodingException e) {
//            throw new RuntimeException(e);  // Cannot happen.
//        }
    }
//
//    public static byte[] decode(String input) throws IllegalArgumentException {
//        if (input.length() == 0) {
//            return new byte[0];
//        }
//        byte[] input58 = new byte[input.length()];
//        // Transform the String to a base58 byte sequence
//        for (int i = 0; i < input.length(); ++i) {
//            char c = input.charAt(i);
//
//            int digit58 = -1;
//            if (c >= 0 && c < 128) {
//                digit58 = INDEXES[c];
//            }
//            if (digit58 < 0) {
//                throw new IllegalArgumentException("Illegal character " + c + " at " + i);
//            }
//
//            input58[i] = (byte) digit58;
//        }
//        // Count leading zeroes
//        int zeroCount = 0;
//        while (zeroCount < input58.length && input58[zeroCount] == 0) {
//            ++zeroCount;
//        }
//        // The encoding
//        byte[] temp = new byte[input.length()];
//        int j = temp.length;
//
//        int startAt = zeroCount;
//        while (startAt < input58.length) {
//            byte mod = divmod256(input58, startAt);
//            if (input58[startAt] == 0) {
//                ++startAt;
//            }
//
//            temp[--j] = mod;
//        }
//        // Do no add extra leading zeroes, move j to first non null byte.
//        while (j < temp.length && temp[j] == 0) {
//            ++j;
//        }
//
//        return copyOfRange(temp, j - zeroCount, temp.length);
//    }
//
//    public static BigInteger decodeToBigInteger(String input) throws IllegalArgumentException {
//        return new BigInteger(1, decode(input));
//    }
//
    //
    // number -> number / 58, returns number % 58
    //
    private static byte divmod58(byte[] number, short startAt) {
        short remainder = 0;
        for (short i = startAt; i < number.length; i++) {
            short digit256 = (short) ((short) number[i] & 0xFF);
            short temp = (short) (remainder * 256 + digit256);

            number[i] = (byte) (temp / 58);

            remainder = (short) (temp % 58);
        }

        return (byte) remainder;
    }

    //
    // number -> number / 256, returns number % 256
    //
    private static byte divmod256(byte[] number58, short startAt) {
        short remainder = 0;
        for (short i = startAt; i < number58.length; i++) {
            short digit58 = (short)((short)number58[i] & (short)0xFF);
            short temp = (short)(remainder * (short)58 + digit58);

            number58[i] = (byte) (temp / 256);

            remainder = (short) (temp % 256);
        }

        return (byte) remainder;
    }

    private static byte[] copyOfRange(byte[] source, short from, short to) {
        byte[] range = new byte[to - from];
        Util.arrayCopyNonAtomic(source, from, range, (short)0, (short)(range.length));
        return range;
    }
//    public static void main(String[] args) {
//    	byte[] Array = new byte[4];
//    	Array[0] = 1;
//    	Array[1] = 2;
//    	Array[2] = 3;
//    	Array[3] = 4;
//
//		System.out.println(encode(Array));
//	}
}
