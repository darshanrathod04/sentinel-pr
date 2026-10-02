package com.sentinelpr.benchmark.cases.sec007;

import java.io.InputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class AdvSec007ReadUnsharedVulnerable {

    public Object parseMessagePayload(InputStream in) throws IOException, ClassNotFoundException {
        // ADVERSARIAL VULNERABILITY: ObjectInputStream.readUnshared without serialization filter
        ObjectInputStream stream = new ObjectInputStream(in);
        return stream.readUnshared();
    }
}
