package javacryption.aes;

import java.util.Date;
import javacryption.exception.CryptoException;
import org.apache.commons.codec.binary.Base64;

public class AesCtr
{
  public static String encrypt(String plaintext, String password, int nBits)
  {
    Rijndael aes = new Rijndael();
    if ((nBits != 128) && (nBits != 192) && (nBits != 256)) {
      throw new CryptoException("Invalid key size (" + nBits + " bits)");
    }
    int nBytes = nBits / 8;
    byte[] pwBytes = new byte[nBytes];
    for (int i = 0; i < nBytes; i++) {
      pwBytes[i] = ((byte)password.charAt(i));
    }
    aes.makeKey(pwBytes, 256, 1);
    byte[] key = aes.encryptBlock(pwBytes, new byte[16]);
    aes.finalize();
    if (nBytes > 16)
    {
      byte[] keySlice = new byte[nBytes - 16];
      for (int i = 0; i < nBytes - 16; i++) {
        keySlice[i] = key[i];
      }
      key = Util.addByteArrays(key, keySlice);
    }
    byte[] counterBlock = new byte[16];
    
    long nonce = new Date().getTime();
    int nonceMs = (int)nonce % 1000;
    int nonceSec = (int)Math.floor(nonce / 1000L);
    int nonceRnd = (int)Math.floor(Math.random() * 65535.0D);
    for (int i = 0; i < 2; i++) {
      counterBlock[i] = ((byte)(nonceMs >>> i * 8 & 0xFF));
    }
    for (int i = 0; i < 2; i++) {
      counterBlock[(i + 2)] = ((byte)(nonceRnd >>> i * 8 & 0xFF));
    }
    for (int i = 0; i < 4; i++) {
      counterBlock[(i + 4)] = ((byte)(nonceSec >>> i * 8 & 0xFF));
    }
    byte[] ctrTxt = new byte[8];
    for (int i = 0; i < 8; i++) {
      ctrTxt[i] = counterBlock[i];
    }
    aes.makeKey(key, 256, 1);
    
    int blockCount = (int)Math.ceil(new Float(plaintext.length()).floatValue() / 
      16.0F);
    
    byte[] ciphertxt = new byte[plaintext.length()];
    for (int b = 0; b < blockCount; b++)
    {
      for (int c = 0; c < 4; c++) {
        counterBlock[(15 - c)] = ((byte)(b >>> c * 8 & 0xFF));
      }
      for (int c = 0; c < 4; c++) {
        counterBlock[(15 - c - 4)] = 0;
      }
      byte[] cipherCntr = aes.encryptBlock(counterBlock, 
        new byte[16]);
      
      int blockLength = b < blockCount - 1 ? 16 : 
        (plaintext.length() - 1) % 16 + 1;
      for (int i = 0; i < blockLength; i++) {
        ciphertxt[(b * 16 + i)] = 
          ((byte)(cipherCntr[i] ^ plaintext.charAt(b * 16 + i)));
      }
    }
    aes.finalize();
    
    byte[] ciphertext = Util.addByteArrays(ctrTxt, ciphertxt);
    
    String ciphertext64 = new String(Base64.encodeBase64(ciphertext));
    
    return ciphertext64;
  }
  
  public static String decrypt(String ciphertext, String password, int nBits)
  {
    Rijndael aes = new Rijndael();
    if ((nBits != 128) && (nBits != 192) && (nBits != 256)) {
      return null;
    }
    byte[] cipherByte = Base64.decodeBase64(ciphertext.getBytes());
    
    int nBytes = nBits / 8;
    byte[] pwBytes = new byte[nBytes];
    for (int i = 0; i < nBytes; i++) {
      pwBytes[i] = ((byte)password.charAt(i));
    }
    aes.makeKey(pwBytes, 256, 1);
    byte[] key = aes.encryptBlock(pwBytes, new byte[16]);
    aes.finalize();
    if (nBytes > 16)
    {
      byte[] keySlice = new byte[nBytes - 16];
      for (int i = 0; i < nBytes - 16; i++) {
        keySlice[i] = key[i];
      }
      key = Util.addByteArrays(key, keySlice);
    }
    byte[] counterBlock = new byte[16];
    for (int i = 0; i < 8; i++) {
      counterBlock[i] = cipherByte[i];
    }
    aes.makeKey(key, 256, 1);
    
    int blockCount = (int)Math.ceil(new Float(cipherByte.length - 8).floatValue() / 
      16.0F);
    
    byte[] plaintxt = new byte[cipherByte.length - 8];
    for (int b = 0; b < blockCount; b++)
    {
      for (int c = 0; c < 4; c++) {
        counterBlock[(15 - c)] = ((byte)(b >>> c * 8 & 0xFF));
      }
      for (int c = 0; c < 4; c++) {
        counterBlock[(15 - c - 4)] = 0;
      }
      byte[] cipherCntr = aes.encryptBlock(counterBlock, 
        new byte[16]);
      
      int blockLength = b < blockCount - 1 ? 16 : 
        (cipherByte.length - 9) % 16 + 1;
      for (int i = 0; i < blockLength; i++) {
        plaintxt[(b * 16 + i)] = 
          ((byte)(cipherCntr[i] ^ cipherByte[(8 + b * 16 + i)]));
      }
    }
    aes.finalize();
    
    String plaintext = new String(plaintxt);
    
    return plaintext;
  }
}
