package javacryption.aes;

public final class Util
{
  public static byte[] addByteArrays(byte[] first, byte[] second)
  {
    byte[] result = new byte[first.length + second.length];
    
    System.arraycopy(first, 0, result, 0, first.length);
    System.arraycopy(second, 0, result, first.length, second.length);
    
    return result;
  }
  
  public static final boolean areEqual(byte[] first, byte[] second)
  {
    int aLength = first.length;
    if (aLength != second.length) {
      return false;
    }
    for (int i = 0; i < aLength; i++) {
      if (first[i] != second[i]) {
        return false;
      }
    }
    return true;
  }
}
