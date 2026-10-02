package com.sentinelpr.benchmark.realistic.arch002_01;

public class CustomerEntity {
    private Long id;
    private String name;
    private String email;

    public CustomerEntity(Long id, String name, String email) {
        this.id = id;
        this.name = name;
        this.email = email;
    }

    public Long getId() { return id; }
    public String getName() { return name; }
    public String getEmail() { return email; }
}
