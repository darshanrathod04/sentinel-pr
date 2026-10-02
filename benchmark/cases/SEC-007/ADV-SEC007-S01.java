package com.sentinelpr.benchmark.cases.sec007;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class AdvSec007FilteredSafe {

    public Object parseValidatedData(byte[] data) throws IOException, ClassNotFoundException {
        // SAFE: Strict allowlist ObjectInputFilter applied before readObject
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(data));
        stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.Number;java.lang.Long;!*"));
        return stream.readObject();
    }
}
