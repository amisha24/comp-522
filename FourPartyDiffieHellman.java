import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class FourPartyDiffieHellman {

    public static void main(String argv[]) throws Exception {
        // Alice creates her own DH key pair with a 2048-bit key size
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

        // This DH parameters can also be constructed by creating a
        // DHParameterSpec object using agreed-upon values
        DHParameterSpec dhParamShared = ((DHPublicKey) aliceKpair.getPublic()).getParams();

        // Bob creates his own DH key pair using the same params
        System.out.println("BOB: Generate DH keypair ...");
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamShared);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        // Carol creates her own DH key pair using the same params
        System.out.println("CAROL: Generate DH keypair ...");
        KeyPairGenerator carolKpairGen = KeyPairGenerator.getInstance("DH");
        carolKpairGen.initialize(dhParamShared);
        KeyPair carolKpair = carolKpairGen.generateKeyPair();

        // David creates his own DH key pair using the same params
        System.out.println("DAVID: Generate DH keypair ...");
        KeyPairGenerator davidKpairGen = KeyPairGenerator.getInstance("DH");
        davidKpairGen.initialize(dhParamShared);
        KeyPair davidKpair = davidKpairGen.generateKeyPair();

        // Alice initialize
        System.out.println("ALICE: Initialize ...");
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        // Bob initialize
        System.out.println("BOB: Initialize ...");
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());

        // Carol initialize
        System.out.println("CAROL: Initialize ...");
        KeyAgreement carolKeyAgree = KeyAgreement.getInstance("DH");
        carolKeyAgree.init(carolKpair.getPrivate());

        // David initialize
        System.out.println("DAVID: Initialize ...");
        KeyAgreement davidKeyAgree = KeyAgreement.getInstance("DH");
        davidKeyAgree.init(davidKpair.getPrivate());

        //Phase1 Alice shares key to Bob
        Key ab = aliceKeyAgree.doPhase(bobKpair.getPublic(), false);
        
        //Phase1 Bob shares key to Carol
        Key bc = bobKeyAgree.doPhase(carolKpair.getPublic(), false);

        //Phase1 Carol shares key to David
        Key cd = carolKeyAgree.doPhase(davidKpair.getPublic(), false);

        //Phase1 David shares key to Alice
        Key da = davidKeyAgree.doPhase(aliceKpair.getPublic(), false);
        
        //Phase2 use Alice and Bob shared key and share with Carol
        Key abc = aliceKeyAgree.doPhase(cd, false);

        //Phase2 use Bob and Carol shared key and share with David
        Key bcd = bobKeyAgree.doPhase(da, false);

        //Phase2 use Carol and David shared key and share with Alice
        Key cda = carolKeyAgree.doPhase(ab, false);

        //Phase2 use David and Alice shared key and share with Bob
        Key dab = davidKeyAgree.doPhase(bc, false);

        
        //Final Phase
        aliceKeyAgree.doPhase(dab, true);
        bobKeyAgree.doPhase(abc, true);
        carolKeyAgree.doPhase(bcd, true);
        davidKeyAgree.doPhase(cda, true);

        // Alice, Bob, and Carol compute their secrets
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        System.out.println("Alice secret: " + toHexString(aliceSharedSecret));

        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
        System.out.println("Bob secret: " + toHexString(bobSharedSecret));

        byte[] carolSharedSecret = carolKeyAgree.generateSecret();
        System.out.println("Carol secret: " + toHexString(carolSharedSecret));

        byte[] davidSharedSecret = davidKeyAgree.generateSecret();
        System.out.println("David secret: " + toHexString(davidSharedSecret));


        // Compare Alice and Bob
        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
            throw new Exception("Alice and Bob differ");
        System.out.println("Alice and Bob are the same");

        // Compare Bob and Carol
        if (!java.util.Arrays.equals(bobSharedSecret, carolSharedSecret))
            throw new Exception("Bob and Carol differ");
        System.out.println("Bob and Carol are the same");

        // Compare Carol and David
        if (!java.util.Arrays.equals(carolSharedSecret, davidSharedSecret))
            throw new Exception("Carol and David differ");
        System.out.println("Carol and David are the same");
    }

    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len - 1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}
