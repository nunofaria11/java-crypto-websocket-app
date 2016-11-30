package pt.nuno.webcrypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import pt.nuno.crypto.CryptoUtils;
import pt.nuno.crypto.EncryptedMessage;
import org.eclipse.jetty.websocket.api.RemoteEndpoint;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketClose;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketConnect;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketMessage;
import org.eclipse.jetty.websocket.api.annotations.WebSocket;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Created by NunoFaria on 24-11-2016.
 */

@WebSocket
public class WebCryptoSocket {

    private List<WebCryptoSocket> users = new CopyOnWriteArrayList<>();
    private Map<WebCryptoSocket, KeyPair> wrapKeyPairs = new HashMap<>();
    private Map<WebCryptoSocket, SecretKey> secretKeys = new HashMap<>();
    private RemoteEndpoint conn;
    private KeyPair signKeyPair = null;
    private JWK signKeyPairJwk = null;

    public WebCryptoSocket() {
        try {
            signKeyPair = CryptoUtils.generateSignKeyPair();
            // Convert to JWK format
            signKeyPairJwk = new RSAKey
                    .Builder((RSAPublicKey) signKeyPair.getPublic())
                    .setPrivateKey((RSAPrivateKey) signKeyPair.getPrivate())
                    .build();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

    }

    @OnWebSocketConnect
    public void onOpen(Session session) {
        this.conn = session.getRemote();
        users.add(this);
    }

    @OnWebSocketClose
    public void onClose(int closeCode, String reason) {
        System.out.println("Closed socket (" + closeCode + "): " + reason);
        WebCryptoSocket thisSocket = this;
        users.remove(thisSocket);
        wrapKeyPairs.remove(thisSocket);
        secretKeys.remove(thisSocket);
    }

    @OnWebSocketMessage
    public void onMessage(Session session, String data) {
        System.out.println("Message received: \"" + data + "\"");
        try {
            String response = respondWithMessage(data);
            System.out.println("Sending message: \"" + response + "\"");
            session.getRemote().sendString(response);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String respondWithMessage(String data) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode response = mapper.createObjectNode();
        KeyPair wrapKeyPair;
        SecretKey secretKey;

        try {
            JsonNode mainNode = mapper.readTree(data);

            JsonNode typeNode = mainNode.path("type");
            String typeValue = typeNode.asText();

            JsonNode receivedDataNode;
            String dataValue;

            response.put("type", typeValue);
            response.put("response", Boolean.TRUE);

            switch (typeValue) {

                case "start":
                    // Share sign publicKey (for clients to verify with)
                    JWK signPubKeyJwk = signKeyPairJwk.toPublicJWK();
                    response.set("signPubKeyJwk", mapper.readTree(signPubKeyJwk.toJSONString()));
                    break;

                case "publicWrapKey":

                    // Generate new wrap/unwrap key pair, to receive a wrapped shared secret later
                    wrapKeyPair = CryptoUtils.generateWrapUnwrapKeyPair();
                    JWK wrapKeyPairJwk = new RSAKey
                            .Builder((RSAPublicKey) wrapKeyPair.getPublic())
                            .setPrivateKey((RSAPrivateKey) wrapKeyPair.getPrivate())
                            .build();
                    JWK wrapPubKeyJwk = wrapKeyPairJwk.toPublicJWK();
                    response.put("message", "wrap/unwrap key pairs generated");

                    // Share publicKey for wrap ...
                    String pubKeyJwk = wrapPubKeyJwk.toJSONString();
                    String pubKeyJwkEncoded = Base64.getEncoder().encodeToString(pubKeyJwk.getBytes());
                    response.put("encodedPubKey", pubKeyJwkEncoded);

                    // ... Sign its Base64 encoded value
                    System.out.println("Signing with: " + signKeyPair.getPrivate());
                    byte[] signature = CryptoUtils.generateSignature(signKeyPair.getPrivate(), pubKeyJwkEncoded.getBytes());
                    String signatureBase64 = Base64.getEncoder().encodeToString(signature);
                    response.put("signature", signatureBase64);

                    System.out.println("Signature (bytes):\n" + Arrays.toString(signature));
                    System.out.println("Signature (b64):\n" + signatureBase64);

                    System.out.println("Encoded pubKey (bytes): " + Arrays.toString(pubKeyJwkEncoded.getBytes()));
                    System.out.println("Encoded pubKey (b64): " + pubKeyJwkEncoded);

                    wrapKeyPairs.put(this, wrapKeyPair);
                    break;

                case "wrappedKey":
                    // Receive the wrapped secret key
                    receivedDataNode = mainNode.path("data");
                    dataValue = receivedDataNode.asText();

                    byte[] wrappedKeyBytes = Base64.getDecoder().decode(dataValue);

                    System.out.println("Wrapped key (bytes=" + wrappedKeyBytes.length + "): " + Arrays.toString(wrappedKeyBytes));

                    wrapKeyPair = wrapKeyPairs.get(this);

                    // ... and unwrap it
                    secretKey = CryptoUtils.unwrapKey(wrapKeyPair.getPrivate(), wrappedKeyBytes);
                    System.out.println("Secret key: " + secretKey);
                    System.out.println("Secret key (bytes=" + secretKey.getEncoded().length + "): " + Arrays.toString(secretKey.getEncoded()));

                    secretKeys.put(this, secretKey);

                    response.put("status", 200);
                    break;

                case "message":
                    // Decrypt message with shared secret key
                    receivedDataNode = mainNode.path("data");
                    JsonNode messageNode = receivedDataNode.path("message");
                    JsonNode ivNode = receivedDataNode.path("iv");

                    String messageValue = messageNode.asText();
                    String ivValue = ivNode.asText();

                    byte[] message = Base64.getDecoder().decode(messageValue);
                    byte[] iv = Base64.getDecoder().decode(ivValue);

                    EncryptedMessage encMessage = new EncryptedMessage(message, iv);
                    secretKey = secretKeys.get(this);
                    System.out.println("Decrypt key: " + secretKey);
                    System.out.println("Decrypt key (bytes=" + secretKey.getEncoded().length + "): " + Arrays.toString(secretKey.getEncoded()));

                    byte[] decryptedBytes = CryptoUtils.decrypt(secretKey, encMessage);
                    String decryptedMessage = new String(decryptedBytes);
                    System.out.println("Decrypted message: \"" + decryptedMessage + "\"");

                    // Encrypt test echo
                    String echoText = "ECHO: <" + decryptedMessage + ">";
                    EncryptedMessage echoMessage = CryptoUtils.encrypt(secretKey, echoText.getBytes());

                    String echoMessageBase64 = Base64.getEncoder().encodeToString(echoMessage.getData());
                    String ivBase64 = Base64.getEncoder().encodeToString(echoMessage.getIv());
                    response.put("message", echoMessageBase64);
                    response.put("iv", ivBase64);

                    response.put("status", 200);
                    break;

                default:
                    response.put("unknown", typeValue);

            }
        } catch (Exception e) {
            e.printStackTrace();
            response.removeAll();
            response.put("error", "Error occurred");
        }
        return response.toString();
    }

}
