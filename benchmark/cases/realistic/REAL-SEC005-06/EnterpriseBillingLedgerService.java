package com.sentinelpr.benchmark.realistic.sec005_06;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * EnterpriseBillingLedgerService - Large enterprise billing engine (~520 LOC).
 * Provides end-to-end accounting logic, tax calculations, invoice reconciliation,
 * discount strategies, audit trail logging, and customer payment operations.
 * Contains an unescaped SQL statement in queryInvoicesByAccount.
 */
public class EnterpriseBillingLedgerService {

    private static final BigDecimal DEFAULT_TAX_RATE = new BigDecimal("0.0825");
    private static final BigDecimal MAX_DISCOUNT_PERCENT = new BigDecimal("0.50");
    private static final Pattern ACCOUNT_ID_PATTERN = Pattern.compile("^[A-Z]{2}-\\d{4}-\\w+$");

    private final Connection connection;
    private final List<String> auditLogs = new ArrayList<>();
    private final Map<String, BigDecimal> customerBalances = new HashMap<>();

    public EnterpriseBillingLedgerService(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection must not be null");
    }

    public record InvoiceLineItem(
            String itemId,
            String description,
            int quantity,
            BigDecimal unitPrice,
            BigDecimal lineTotal
    ) {}

    public record InvoiceDetails(
            String invoiceId,
            String accountId,
            LocalDate issueDate,
            LocalDate dueDate,
            BigDecimal subtotal,
            BigDecimal taxAmount,
            BigDecimal discountAmount,
            BigDecimal finalTotal,
            String paymentStatus,
            List<InvoiceLineItem> items
    ) {}

    public record PaymentReceipt(
            String receiptId,
            String invoiceId,
            BigDecimal amountPaid,
            Instant timestamp,
            String confirmationCode
    ) {}

    public record TaxBreakdown(
            BigDecimal stateTax,
            BigDecimal municipalTax,
            BigDecimal specialDistrictTax,
            BigDecimal totalTax
    ) {}

    public record CustomerBillingProfile(
            String accountId,
            String companyName,
            String taxExemptId,
            String currency,
            boolean autoPayEnabled
    ) {}

    // ─── 1. Primary Invoice Query (Contains Vulnerability) ─────────────────────

    public List<String> queryInvoicesByAccount(String accountId) {
        validateAccountId(accountId);
        List<String> invoiceIds = new ArrayList<>();

        try {
            Statement statement = connection.createStatement();
            String sql = "SELECT invoice_id FROM billing_invoices WHERE account_id = '" + accountId + "'";
            ResultSet rs = statement.executeQuery(sql);
            while (rs.next()) {
                invoiceIds.add(rs.getString("invoice_id"));
            }
        } catch (SQLException e) {
            logAudit("ERROR", "Query invoices failed for account: " + accountId);
            throw new RuntimeException("Database error querying invoices", e);
        }

        logAudit("INFO", "Queried " + invoiceIds.size() + " invoices for account " + accountId);
        return invoiceIds;
    }

    // ─── 2. Invoice Generation & Math Calculations ────────────────────────────

    public InvoiceDetails createInvoice(
            String accountId,
            List<InvoiceLineItem> rawItems,
            BigDecimal discountPercent,
            String jurisdiction
    ) {
        validateAccountId(accountId);
        if (rawItems == null || rawItems.isEmpty()) {
            throw new IllegalArgumentException("Invoice items cannot be empty");
        }

        BigDecimal subtotal = BigDecimal.ZERO;
        List<InvoiceLineItem> calculatedItems = new ArrayList<>();
        for (InvoiceLineItem item : rawItems) {
            BigDecimal lineTotal = item.unitPrice().multiply(BigDecimal.valueOf(item.quantity()))
                    .setScale(2, RoundingMode.HALF_UP);
            calculatedItems.add(new InvoiceLineItem(item.itemId(), item.description(), item.quantity(), item.unitPrice(), lineTotal));
            subtotal = subtotal.add(lineTotal);
        }

        BigDecimal safeDiscount = discountPercent != null ? discountPercent : BigDecimal.ZERO;
        if (safeDiscount.compareTo(MAX_DISCOUNT_PERCENT) > 0) {
            safeDiscount = MAX_DISCOUNT_PERCENT;
        }

        BigDecimal discountAmount = subtotal.multiply(safeDiscount).setScale(2, RoundingMode.HALF_UP);
        BigDecimal discountedSubtotal = subtotal.subtract(discountAmount);

        TaxBreakdown taxes = calculateTaxes(discountedSubtotal, jurisdiction);
        BigDecimal finalTotal = discountedSubtotal.add(taxes.totalTax());

        String invoiceId = "INV-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(Locale.ROOT);
        LocalDate today = LocalDate.now();
        LocalDate due = today.plusDays(30);

        InvoiceDetails invoice = new InvoiceDetails(
                invoiceId, accountId, today, due, subtotal, taxes.totalTax(), discountAmount, finalTotal, "PENDING", calculatedItems
        );

        persistInvoice(invoice);
        logAudit("CREATE", "Generated invoice " + invoiceId + " for amount " + finalTotal);
        return invoice;
    }

    public TaxBreakdown calculateTaxes(BigDecimal amount, String jurisdiction) {
        if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
            return new TaxBreakdown(BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO);
        }

        BigDecimal stateRate;
        BigDecimal municipalRate;
        BigDecimal districtRate;

        if ("CA".equalsIgnoreCase(jurisdiction)) {
            stateRate = new BigDecimal("0.0725");
            municipalRate = new BigDecimal("0.0150");
            districtRate = new BigDecimal("0.0050");
        } else if ("NY".equalsIgnoreCase(jurisdiction)) {
            stateRate = new BigDecimal("0.0400");
            municipalRate = new BigDecimal("0.0450");
            districtRate = new BigDecimal("0.00375");
        } else if ("TX".equalsIgnoreCase(jurisdiction)) {
            stateRate = new BigDecimal("0.0625");
            municipalRate = new BigDecimal("0.0200");
            districtRate = BigDecimal.ZERO;
        } else {
            stateRate = DEFAULT_TAX_RATE;
            municipalRate = BigDecimal.ZERO;
            districtRate = BigDecimal.ZERO;
        }

        BigDecimal stateTax = amount.multiply(stateRate).setScale(2, RoundingMode.HALF_UP);
        BigDecimal muniTax = amount.multiply(municipalRate).setScale(2, RoundingMode.HALF_UP);
        BigDecimal distTax = amount.multiply(districtRate).setScale(2, RoundingMode.HALF_UP);
        BigDecimal total = stateTax.add(muniTax).add(distTax);

        return new TaxBreakdown(stateTax, muniTax, distTax, total);
    }

    // ─── 3. Payment Processing & Settlement ──────────────────────────────────

    public PaymentReceipt recordPayment(String invoiceId, BigDecimal paymentAmount, String paymentMethod) {
        Objects.requireNonNull(invoiceId, "invoiceId cannot be null");
        Objects.requireNonNull(paymentAmount, "paymentAmount cannot be null");

        if (paymentAmount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Payment amount must be positive");
        }

        InvoiceDetails invoice = loadInvoice(invoiceId);
        if (invoice == null) {
            throw new IllegalStateException("Invoice not found: " + invoiceId);
        }

        if ("PAID".equalsIgnoreCase(invoice.paymentStatus())) {
            throw new IllegalStateException("Invoice " + invoiceId + " is already fully settled");
        }

        String receiptId = "RCP-" + UUID.randomUUID().toString().substring(0, 10).toUpperCase(Locale.ROOT);
        String confirmation = "CONF-" + Math.abs(Objects.hash(invoiceId, paymentAmount, Instant.now()));

        PaymentReceipt receipt = new PaymentReceipt(receiptId, invoiceId, paymentAmount, Instant.now(), confirmation);
        savePaymentRecord(receipt, paymentMethod);

        if (paymentAmount.compareTo(invoice.finalTotal()) >= 0) {
            updateInvoiceStatus(invoiceId, "PAID");
        } else {
            updateInvoiceStatus(invoiceId, "PARTIAL");
        }

        adjustCustomerBalance(invoice.accountId(), paymentAmount.negate());
        logAudit("PAYMENT", "Applied payment " + receiptId + " to invoice " + invoiceId);
        return receipt;
    }

    public boolean applyCreditMemo(String accountId, String invoiceId, BigDecimal creditAmount) {
        validateAccountId(accountId);
        if (creditAmount.compareTo(BigDecimal.ZERO) <= 0) {
            return false;
        }

        BigDecimal balance = customerBalances.getOrDefault(accountId, BigDecimal.ZERO);
        if (balance.compareTo(creditAmount) < 0) {
            return false;
        }

        customerBalances.put(accountId, balance.subtract(creditAmount));
        logAudit("CREDIT", "Applied credit of " + creditAmount + " to account " + accountId);
        return true;
    }

    // ─── 4. Ledger Reconciliation & Auditing ──────────────────────────────────

    public Map<String, Object> reconcileLedgerBatch(LocalDate cycleDate) {
        Map<String, Object> report = new HashMap<>();
        long reconciledCount = 0;
        BigDecimal totalVolume = BigDecimal.ZERO;

        String sql = "SELECT invoice_id, final_total, payment_status FROM billing_invoices WHERE issue_date <= ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setDate(1, java.sql.Date.valueOf(cycleDate));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    reconciledCount++;
                    totalVolume = totalVolume.add(rs.getBigDecimal("final_total"));
                }
            }
        } catch (SQLException e) {
            logAudit("ERROR", "Reconciliation query failed: " + e.getMessage());
            throw new RuntimeException("Reconciliation failure", e);
        }

        report.put("cycleDate", cycleDate);
        report.put("reconciledInvoices", reconciledCount);
        report.put("totalVolume", totalVolume);
        report.put("status", "BALANCED");
        logAudit("RECONCILE", "Batch reconciliation completed for " + cycleDate + ", count=" + reconciledCount);
        return report;
    }

    public List<String> identifyOverdueAccounts(int thresholdDays) {
        LocalDate cutoff = LocalDate.now().minusDays(Math.max(1, thresholdDays));
        String sql = "SELECT DISTINCT account_id FROM billing_invoices WHERE due_date < ? AND payment_status != 'PAID'";
        List<String> overdueAccounts = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setDate(1, java.sql.Date.valueOf(cutoff));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    overdueAccounts.add(rs.getString("account_id"));
                }
            }
        } catch (SQLException e) {
            logAudit("ERROR", "Failed to retrieve overdue accounts: " + e.getMessage());
        }

        return overdueAccounts;
    }

    public BigDecimal computeMonthlyRecurringRevenue(LocalDate month) {
        LocalDate startOfMonth = month.withDayOfMonth(1);
        LocalDate endOfMonth = month.withDayOfMonth(month.lengthOfMonth());

        String sql = "SELECT SUM(final_total) AS mrr FROM billing_invoices WHERE issue_date >= ? AND issue_date <= ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setDate(1, java.sql.Date.valueOf(startOfMonth));
            ps.setDate(2, java.sql.Date.valueOf(endOfMonth));
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    BigDecimal mrr = rs.getBigDecimal("mrr");
                    return mrr != null ? mrr : BigDecimal.ZERO;
                }
            }
        } catch (SQLException e) {
            logAudit("ERROR", "MRR calculation failed: " + e.getMessage());
        }
        return BigDecimal.ZERO;
    }

    public Set<String> findSuspiciousDiscounts(BigDecimal thresholdPercent) {
        String sql = "SELECT invoice_id, subtotal, discount_amount FROM billing_invoices WHERE subtotal > 0";
        Set<String> suspicious = new HashSet<>();

        try (PreparedStatement ps = connection.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                BigDecimal sub = rs.getBigDecimal("subtotal");
                BigDecimal disc = rs.getBigDecimal("discount_amount");
                if (sub != null && disc != null && sub.compareTo(BigDecimal.ZERO) > 0) {
                    BigDecimal pct = disc.divide(sub, 4, RoundingMode.HALF_UP);
                    if (pct.compareTo(thresholdPercent) > 0) {
                        suspicious.add(rs.getString("invoice_id"));
                    }
                }
            }
        } catch (SQLException e) {
            logAudit("ERROR", "Suspicious discount search failed: " + e.getMessage());
        }
        return suspicious;
    }

    // ─── 5. Persistence & Helper Routines ─────────────────────────────────────

    private void persistInvoice(InvoiceDetails inv) {
        String sql = "INSERT INTO billing_invoices (invoice_id, account_id, issue_date, due_date, subtotal, tax_amount, discount_amount, final_total, payment_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, inv.invoiceId());
            ps.setString(2, inv.accountId());
            ps.setDate(3, java.sql.Date.valueOf(inv.issueDate()));
            ps.setDate(4, java.sql.Date.valueOf(inv.dueDate()));
            ps.setBigDecimal(5, inv.subtotal());
            ps.setBigDecimal(6, inv.taxAmount());
            ps.setBigDecimal(7, inv.discountAmount());
            ps.setBigDecimal(8, inv.finalTotal());
            ps.setString(9, inv.paymentStatus());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to persist invoice", e);
        }
    }

    private InvoiceDetails loadInvoice(String invoiceId) {
        String sql = "SELECT invoice_id, account_id, issue_date, due_date, subtotal, tax_amount, discount_amount, final_total, payment_status FROM billing_invoices WHERE invoice_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, invoiceId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new InvoiceDetails(
                            rs.getString("invoice_id"),
                            rs.getString("account_id"),
                            rs.getDate("issue_date").toLocalDate(),
                            rs.getDate("due_date").toLocalDate(),
                            rs.getBigDecimal("subtotal"),
                            rs.getBigDecimal("tax_amount"),
                            rs.getBigDecimal("discount_amount"),
                            rs.getBigDecimal("final_total"),
                            rs.getString("payment_status"),
                            Collections.emptyList()
                    );
                }
            }
        } catch (SQLException e) {
            logAudit("ERROR", "Invoice lookup error for " + invoiceId);
        }
        return null;
    }

    private void savePaymentRecord(PaymentReceipt receipt, String paymentMethod) {
        String sql = "INSERT INTO payment_receipts (receipt_id, invoice_id, amount_paid, paid_at, confirmation_code, method) VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, receipt.receiptId());
            ps.setString(2, receipt.invoiceId());
            ps.setBigDecimal(3, receipt.amountPaid());
            ps.setTimestamp(4, java.sql.Timestamp.from(receipt.timestamp()));
            ps.setString(5, receipt.confirmationCode());
            ps.setString(6, paymentMethod != null ? paymentMethod : "UNKNOWN");
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to record payment", e);
        }
    }

    private void updateInvoiceStatus(String invoiceId, String status) {
        String sql = "UPDATE billing_invoices SET payment_status = ? WHERE invoice_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setString(2, invoiceId);
            ps.executeUpdate();
        } catch (SQLException e) {
            logAudit("WARN", "Status update failed for invoice: " + invoiceId);
        }
    }

    private void adjustCustomerBalance(String accountId, BigDecimal delta) {
        customerBalances.merge(accountId, delta, BigDecimal::add);
    }

    private void validateAccountId(String accountId) {
        if (accountId == null || accountId.isBlank()) {
            throw new IllegalArgumentException("Account ID must not be blank");
        }
    }

    private void logAudit(String level, String message) {
        String entry = String.format("[%s] %s: %s", level, Instant.now(), message);
        auditLogs.add(entry);
        if (auditLogs.size() > 1000) {
            auditLogs.remove(0);
        }
    }

    public List<String> getRecentAuditLogs(int count) {
        int from = Math.max(0, auditLogs.size() - count);
        return new ArrayList<>(auditLogs.subList(from, auditLogs.size()));
    }

    public BigDecimal getCustomerBalance(String accountId) {
        return customerBalances.getOrDefault(accountId, BigDecimal.ZERO);
    }

    public BigDecimal calculateProratedSubscription(
            BigDecimal monthlyRate,
            LocalDate startDate,
            LocalDate cancellationDate
    ) {
        Objects.requireNonNull(monthlyRate, "monthlyRate cannot be null");
        Objects.requireNonNull(startDate, "startDate cannot be null");
        Objects.requireNonNull(cancellationDate, "cancellationDate cannot be null");

        if (cancellationDate.isBefore(startDate)) {
            throw new IllegalArgumentException("Cancellation date cannot precede start date");
        }

        int daysInMonth = startDate.lengthOfMonth();
        long activeDays = java.time.temporal.ChronoUnit.DAYS.between(startDate, cancellationDate) + 1;
        if (activeDays >= daysInMonth) {
            return monthlyRate.setScale(2, RoundingMode.HALF_UP);
        }

        BigDecimal dailyRate = monthlyRate.divide(BigDecimal.valueOf(daysInMonth), 4, RoundingMode.HALF_UP);
        return dailyRate.multiply(BigDecimal.valueOf(activeDays)).setScale(2, RoundingMode.HALF_UP);
    }

    public record AgingSchedule(
            BigDecimal current,
            BigDecimal thirtyDays,
            BigDecimal sixtyDays,
            BigDecimal ninetyPlusDays
    ) {}

    public AgingSchedule computeCustomerAgingSchedule(String accountId) {
        validateAccountId(accountId);
        LocalDate now = LocalDate.now();

        BigDecimal cur = BigDecimal.ZERO;
        BigDecimal thirty = BigDecimal.ZERO;
        BigDecimal sixty = BigDecimal.ZERO;
        BigDecimal ninety = BigDecimal.ZERO;

        String sql = "SELECT due_date, final_total FROM billing_invoices WHERE account_id = ? AND payment_status != 'PAID'";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    LocalDate due = rs.getDate("due_date").toLocalDate();
                    BigDecimal amt = rs.getBigDecimal("final_total");
                    long overdueDays = java.time.temporal.ChronoUnit.DAYS.between(due, now);

                    if (overdueDays <= 0) {
                        cur = cur.add(amt);
                    } else if (overdueDays <= 30) {
                        thirty = thirty.add(amt);
                    } else if (overdueDays <= 60) {
                        sixty = sixty.add(amt);
                    } else {
                        ninety = ninety.add(amt);
                    }
                }
            }
        } catch (SQLException e) {
            logAudit("ERROR", "Failed to compute aging schedule for " + accountId);
        }

        return new AgingSchedule(cur, thirty, sixty, ninety);
    }

    public BigDecimal convertCurrency(BigDecimal amount, String fromCurrency, String toCurrency) {
        if (amount == null || fromCurrency == null || toCurrency == null) {
            return BigDecimal.ZERO;
        }
        if (fromCurrency.equalsIgnoreCase(toCurrency)) {
            return amount;
        }

        Map<String, BigDecimal> fxRatesToUsd = Map.of(
                "USD", BigDecimal.ONE,
                "EUR", new BigDecimal("1.08"),
                "GBP", new BigDecimal("1.26"),
                "CAD", new BigDecimal("0.74"),
                "AUD", new BigDecimal("0.65")
        );

        BigDecimal fromRate = fxRatesToUsd.getOrDefault(fromCurrency.toUpperCase(Locale.ROOT), BigDecimal.ONE);
        BigDecimal toRate = fxRatesToUsd.getOrDefault(toCurrency.toUpperCase(Locale.ROOT), BigDecimal.ONE);

        BigDecimal inUsd = amount.multiply(fromRate);
        return inUsd.divide(toRate, 2, RoundingMode.HALF_UP);
    }

    public boolean issueRefund(String receiptId, BigDecimal refundAmount, String reason) {
        Objects.requireNonNull(receiptId, "receiptId required");
        Objects.requireNonNull(refundAmount, "refundAmount required");

        if (refundAmount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Refund amount must be positive");
        }

        String sql = "INSERT INTO billing_refunds (refund_id, receipt_id, refund_amount, reason, created_at) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, "REF-" + UUID.randomUUID().toString().substring(0, 8));
            ps.setString(2, receiptId);
            ps.setBigDecimal(3, refundAmount);
            ps.setString(4, reason != null ? reason : "CUSTOMER_REQUEST");
            ps.setTimestamp(5, java.sql.Timestamp.from(Instant.now()));
            int rows = ps.executeUpdate();
            logAudit("REFUND", "Issued refund for receipt " + receiptId + " amount=" + refundAmount);
            return rows > 0;
        } catch (SQLException e) {
            logAudit("ERROR", "Refund creation failed: " + e.getMessage());
            return false;
        }
    }

    public void clearAuditHistory() {
        auditLogs.clear();
    }
}
