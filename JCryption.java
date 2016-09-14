ackage javacryption.jcryption;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javacryption.exception.CryptoException;

public class JCryption
{
  private KeyPair keyPair = null;
  private int keyLength = 1024;
  
  public JCryption()
  {
    generateKeyPair(this.keyLength);
  }
  
  public JCryption(int keyLength)
  {
    generateKeyPair(keyLength);
  }
  
  public JCryption(KeyPair keyPair)
  {
    setKeyPair(keyPair);
  }
  
  public KeyPair getKeyPair()
  {
    return this.keyPair;
  }
  
  public void setKeyPair(KeyPair keyPair)
  {
    this.keyPair = keyPair;
    this.keyLength = ((RSAPublicKey)keyPair.getPublic()).getModulus()
      .bitLength();
  }
  
  public int getKeyLength()
  {
    return this.keyLength;
  }
  
  public void generateKeyPair(int keyLength)
  {
    try
    {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(keyLength);
      this.keyPair = kpg.generateKeyPair();
      this.keyLength = keyLength;
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new CryptoException("Error obtaining RSA algorithm", e);
    }
  }
  
  public String getKeyModulus()
  {
    RSAPublicKey publicKey = (RSAPublicKey)this.keyPair.getPublic();
    return publicKey.getModulus().toString(16);
  }
  
  public String getPublicExponent()
  {
    RSAPublicKey publicKey = (RSAPublicKey)this.keyPair.getPublic();
    return publicKey.getPublicExponent().toString(16);
  }
  
  public int getMaxDigits()
  {
    return this.keyLength * 2 / 16 + 3;
  }
  
  public String decrypt(String encrypted)
  {
    RSAPublicKey publicKey = (RSAPublicKey)this.keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey)this.keyPair.getPrivate();
    String[] blocks = encrypted.split("\\s");
    String result = "";
    for (int i = 0; i < blocks.length; i++)
    {
      BigInteger data = new BigInteger(blocks[i], 16);
      BigInteger decryptedBlock = data.modPow(
        privateKey.getPrivateExponent(), publicKey.getModulus());
      result = result + decodeBigIntToHex(decryptedBlock);
    }
    return redundancyCheck(result);
  }
  
  private String decodeBigIntToHex(BigInteger bigint)
  {
    String message = "";
    while (bigint.compareTo(new BigInteger("0")) != 0)
    {
      BigInteger ascii = bigint.mod(new BigInteger("256"));
      bigint = bigint.divide(new BigInteger("256"));
      message = message + (char)ascii.intValue();
    }
    return message;
  }
  
  private String redundancyCheck(String string)
  {
    String r1 = string.substring(0, 2);
    String r2 = string.substring(2);
    int check = Integer.parseInt(r1, 16);
    String value = r2;
    int sum = 0;
    for (int i = 0; i < value.length(); i++) {
      sum += value.charAt(i);
    }
    if (check == (sum & 0xFF)) {
      return value;
    }
    return null;
  }
}
