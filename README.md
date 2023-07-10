## Threshold Signature using Ed25519

A pure Java implementation of Threshold Signature.

Threshold signature schemes are a way of generating a single digital signature from multiple signers that can be then validated by another party that has a public key of the participants.

T out of N participants need to sign in order for the threshold signature to be valid.

Part of [Weavechain](https://weavechain.com): The Layer-0 For Data

### Usage

#### Gradle Groovy DSL

```
implementation 'com.weavechain:threshold-sig:1.1'
```

#### Gradle Kotlin DSL

```
implementation("com.weavechain:threshold-sig:1.1")
```

##### Apache Maven

```xml
<dependency>
  <groupId>com.weavechain</groupId>
  <artifactId>threshold-sig</artifactId>
  <version>1.1</version>
</dependency>
```

#### Sample

```java
int T = 2;
int N = 3;

Set<Integer> nodes = new HashSet<>();
nodes.add(0);
nodes.add(1);

String toSign = "test";
ThresholdSigEd25519 tsig = new ThresholdSigEd25519(T, N);

//done by coordinator
ThresholdSigEd25519Params params = tsig.generate();

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
System.out.println(check ? "Success" : "Fail");
```

#### Weavechain

Read more about Weavechain at [https://docs.weavechain.com](https://docs.weavechain.com)