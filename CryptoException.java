ackage javacryption.exception;

public class CryptoException
  extends RuntimeException
{
  private static final long serialVersionUID = 2937872982389908084L;
  
  public CryptoException() {}
  
  public CryptoException(String message)
  {
    super(message);
  }
  
  public CryptoException(Throwable cause)
  {
    super(cause);
  }
  
  public CryptoException(String message, Throwable cause)
  {
    super(message, cause);
  }
}
