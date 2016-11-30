package crypto;

/**
 * Created by NunoFaria on 29-11-2016.
 */
public class EncryptedMessage {

    private final byte[] data;
    private final byte[] iv;

    public EncryptedMessage(byte[] data, byte[] iv) {
        this.data = data;
        this.iv = iv;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getIv() {
        return iv;
    }
}
