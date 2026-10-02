package com.sentinelpr.benchmark.realistic.sec007_01;

import org.springframework.stereotype.Service;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;

@Service
public class PayloadDeserializerService {

    public Object deserializePayload(InputStream inStream) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(inStream);
        return ois.readObject();
    }
}
