package com.weavechain.sig;

import com.weavechain.curve25519.CompressedEdwardsY;
import com.weavechain.curve25519.EdwardsPoint;
import com.weavechain.curve25519.Scalar;
import com.google.common.truth.Truth;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ThresholdSigEd25519Test {

    @BeforeClass
    public void setUp() {
    }

    @Test
    protected void testSignature() throws Exception {
        String toSign = "test";
        ThresholdSigEd25519 tsig = new ThresholdSigEd25519(4, 7);

        //done by coordinator
        ThresholdSigEd25519Params params = tsig.generate();

        Set<Integer> nodes = new HashSet<>();
        nodes.add(1);
        nodes.add(3);
        nodes.add(4);
        nodes.add(6);

        //Round 1: gather from each node
        List<EdwardsPoint> Ri = tsig.gatherRi(params, toSign, nodes);

        //done by coordinator
        EdwardsPoint R = tsig.computeR(Ri);
        Scalar k = tsig.computeK(params.getPublicKey(), R, toSign);

        //Round 2: gather from each node
        List<Scalar> res = tsig.gatherSignatures(params, k, nodes);

        //done by coordinator
        byte[] signature = tsig.computeSignature(R, res);

        //done by validator
        boolean check = ThresholdSigEd25519.verify(params.getPublicKey(), signature, toSign.getBytes(StandardCharsets.UTF_8));
        Truth.assertThat(check).isTrue();
    }


    public static ThresholdSigEd25519Params combine(ThresholdSigEd25519Params... params) {
        try {
            List<Scalar> pshares = new ArrayList<>();
            for (int i = 0; i < params.length; i++) {
                pshares.add(Scalar.ZERO);
            }

            Scalar pvk = null;
            EdwardsPoint pub = EdwardsPoint.IDENTITY;
            for (ThresholdSigEd25519Params p : params) {
                pub = pub.add(new CompressedEdwardsY(p.getPublicKey()).decompress());
                for (int i = 0; i < params.length; i++) {
                    pshares.set(i, pshares.get(i).add(p.getPrivateShares().get(i)));
                }
            }

            return new ThresholdSigEd25519Params(pvk, pub.compress().toByteArray(), pshares, null);
        } catch (Exception e) {
            System.out.println(e.toString());
            return null;
        }
    }

    @Test
    protected void testSignaturePedDKG() throws Exception {
        String toSign = "test";
        ThresholdSigEd25519 tsig = new ThresholdSigEd25519(3, 5);

        //each party has some randomness and does the sharing scheme
        ThresholdSigEd25519Params params1 = tsig.generate();
        ThresholdSigEd25519Params params2 = tsig.generate();
        ThresholdSigEd25519Params params3 = tsig.generate();
        ThresholdSigEd25519Params params4 = tsig.generate();
        ThresholdSigEd25519Params params5 = tsig.generate();

        //simulate each party summing their private share and computing the aggregated public key
        ThresholdSigEd25519Params params = combine(params1, params2, params3, params4, params5);

        Set<Integer> nodes = new HashSet<>();
        nodes.add(1);
        nodes.add(3);
        nodes.add(4);

        //Round 1: gather from each node
        List<EdwardsPoint> Ri = tsig.gatherRi(params, toSign, nodes);

        //done by coordinator
        EdwardsPoint R = tsig.computeR(Ri);
        Scalar k = tsig.computeK(params.getPublicKey(), R, toSign);

        //Round 2: gather from each node
        List<Scalar> res = tsig.gatherSignatures(params, k, nodes);

        //done by coordinator
        byte[] signature = tsig.computeSignature(R, res);

        //done by validator
        boolean check = ThresholdSigEd25519.verify(params.getPublicKey(), signature, toSign.getBytes(StandardCharsets.UTF_8));
        Truth.assertThat(check).isTrue();
    }
}
