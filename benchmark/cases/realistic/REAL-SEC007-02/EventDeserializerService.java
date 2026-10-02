package com.sentinelpr.benchmark.realistic.sec007_02;

import org.springframework.stereotype.Service;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

@Service
public class EventDeserializerService {

    public Object safelyDeserializeEvent(InputStream inputStream) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.*;java.util.*;!*"));
        return ois.readObject();
    }
}
