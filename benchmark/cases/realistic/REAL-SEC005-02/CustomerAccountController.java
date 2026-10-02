package com.sentinelpr.benchmark.realistic.sec005_02;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CustomerAccountController {

    private final CustomerAccountService accountService;

    public CustomerAccountController(CustomerAccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping("/api/accounts/{accountId}")
    public String getAccount(@PathVariable String accountId) {
        return accountService.findAccountById(accountId);
    }
}
