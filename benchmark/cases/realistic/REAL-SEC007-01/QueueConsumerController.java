package com.sentinelpr.benchmark.realistic.sec007_01;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.io.ByteArrayInputStream;
import java.io.IOException;

@RestController
public class QueueConsumerController {

    private final PayloadDeserializerService deserializerService;

    public QueueConsumerController(PayloadDeserializerService deserializerService) {
        this.deserializerService = deserializerService;
    }

    @PostMapping("/api/queue/consume")
    public String consumeMessage(@RequestBody byte[] payload) throws IOException, ClassNotFoundException {
        Object obj = deserializerService.deserializePayload(new ByteArrayInputStream(payload));
        return obj != null ? obj.toString() : "null";
    }
}
