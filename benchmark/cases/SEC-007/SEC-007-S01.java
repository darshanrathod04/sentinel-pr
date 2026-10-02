package com.sentinelpr.benchmark.cases.sec007;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class Sec007InsecureDeserializationSafe {

    public Object readPayload(InputStream inputStream) throws IOException, ClassNotFoundException {
        // SAFE: Strict ObjectInputFilter limiting allowed classes to String
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.String;!*"));
        return ois.readObject();
    }
}
