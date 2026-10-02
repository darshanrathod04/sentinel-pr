package com.sentinelpr.benchmark.realistic.sec005_02;

import org.springframework.stereotype.Service;

@Service
public class CustomerAccountService {

    private final CustomerAccountRepository repository;

    public CustomerAccountService(CustomerAccountRepository repository) {
        this.repository = repository;
    }

    public String findAccountById(String accountId) {
        return repository.queryAccount(accountId);
    }
}
