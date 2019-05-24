package extension.utils;

public class ArrayUtils {

  public static byte[] concat(byte[] ...arrays) {
    int length = 0;
    for (byte[] array : arrays) {
      length += array.length;
    }
    byte[] result = new byte[length];
    int pos = 0;
    for (byte[] array : arrays) {
      for (byte element : array) {
        result[pos] = element;
        pos++;
      }
    }
    return result;
  }

}
