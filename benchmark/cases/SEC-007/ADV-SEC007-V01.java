package com.sentinelpr.benchmark.cases.sec007;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class AdvSec007ReadObjectVulnerable {

    public Object parseSerializedData(byte[] serializedBytes) throws IOException, ClassNotFoundException {
        // ADVERSARIAL VULNERABILITY: ObjectInputStream.readObject without serialization filter
        ByteArrayInputStream bais = new ByteArrayInputStream(serializedBytes);
        ObjectInputStream stream = new ObjectInputStream(bais);
        return stream.readObject();
    }
}
