package com.sentinelpr.benchmark.realistic.sec007_02;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.io.ByteArrayInputStream;
import java.io.IOException;

@RestController
public class EventReceiverController {

    private final EventDeserializerService eventDeserializerService;

    public EventReceiverController(EventDeserializerService eventDeserializerService) {
        this.eventDeserializerService = eventDeserializerService;
    }

    @PostMapping("/api/events/receive")
    public String receiveEvent(@RequestBody byte[] rawData) throws IOException, ClassNotFoundException {
        Object event = eventDeserializerService.safelyDeserializeEvent(new ByteArrayInputStream(rawData));
        return event != null ? event.toString() : "empty";
    }
}
