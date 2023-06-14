package com.weavechain.sig;

import com.weavechain.curve25519.EdwardsPoint;
import com.weavechain.curve25519.Scalar;
import com.google.common.truth.Truth;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class ThresholdSigEd25519Test {

    @BeforeClass
    public void setUp() {
    }

    @Test
    protected void testSignature() throws Exception {
        String toSign = "test";
        ThresholdSigEd25519 tsig = new ThresholdSigEd25519(2, 3);

        //done by coordinator
        ThresholdSigEd25519Params params = tsig.generate();

        //Round 1: gather from each node
        List<EdwardsPoint> Ri = tsig.gatherRi(params, toSign);

        //done by coordinator
        EdwardsPoint R = tsig.computeR(Ri);
        Scalar k = tsig.computeK(params.getPublicKey(), R, toSign);

        //Round 2: gather from each node
        List<Scalar> res = tsig.gatherSignatures(params, k);

        //done by coordinator
        byte[] signature = tsig.computeSignature(R, res);

        //done by validator
        boolean check = ThresholdSigEd25519.verify(params.getPublicKey(), signature, toSign.getBytes(StandardCharsets.UTF_8));
        Truth.assertThat(check).isTrue();
    }
}
