package com.sentinelpr.benchmark.cases.sec007;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;

public class Sec007InsecureDeserializationVulnerable {

    public Object readPayload(InputStream inputStream) throws IOException, ClassNotFoundException {
        // INTENTIONAL VULNERABILITY: ObjectInputStream.readObject() without active filtering
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        return ois.readObject();
    }
}
