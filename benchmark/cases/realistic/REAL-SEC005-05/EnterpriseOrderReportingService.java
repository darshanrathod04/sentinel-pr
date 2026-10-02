package com.sentinelpr.benchmark.realistic.sec005_05;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * EnterpriseOrderReportingService - Large realistic enterprise service.
 * Handles order aggregation, audit logging, multi-criteria filtering, and DTO projection.
 * Employs safe parameterized queries with PreparedStatement placeholders.
 */
public class EnterpriseOrderReportingService {

    private static final Pattern ORDER_CODE_PATTERN = Pattern.compile("^[A-Z]{3}-\\d{6}$");
    private static final Set<String> ALLOWED_SORT_COLUMNS = Set.of("created_at", "total_amount", "customer_id", "status");
    private static final int DEFAULT_PAGE_SIZE = 50;
    private static final int MAX_PAGE_SIZE = 500;

    private final Connection connection;
    private final Map<String, Long> executionMetrics = new HashMap<>();

    public EnterpriseOrderReportingService(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection must not be null");
    }

    public record OrderSummaryDto(
            String orderId,
            String customerId,
            double totalAmount,
            String status,
            Instant createdAt,
            List<String> lineItemSkus
    ) {}

    public record ReportQueryCriteria(
            String customerId,
            String status,
            LocalDate startDate,
            LocalDate endDate,
            int pageNumber,
            int pageSize,
            String sortBy,
            boolean ascending
    ) {}

    public record PaginatedReportResult(
            List<OrderSummaryDto> items,
            int pageNumber,
            int pageSize,
            long totalRecords,
            long executionDurationMs
    ) {}

    public PaginatedReportResult generateOrderReport(ReportQueryCriteria criteria) {
        long startTime = System.nanoTime();
        validateCriteria(criteria);

        int sanitizedPage = Math.max(0, criteria.pageNumber());
        int sanitizedSize = Math.min(MAX_PAGE_SIZE, Math.max(1, criteria.pageSize() > 0 ? criteria.pageSize() : DEFAULT_PAGE_SIZE));
        String sanitizedSort = ALLOWED_SORT_COLUMNS.contains(criteria.sortBy()) ? criteria.sortBy() : "created_at";
        String direction = criteria.ascending() ? "ASC" : "DESC";

        long totalCount = countMatchingOrders(criteria);
        if (totalCount == 0) {
            long duration = (System.nanoTime() - startTime) / 1_000_000;
            return new PaginatedReportResult(Collections.emptyList(), sanitizedPage, sanitizedSize, 0L, duration);
        }

        List<OrderSummaryDto> items = fetchOrderRows(criteria, sanitizedPage, sanitizedSize, sanitizedSort, direction);
        long duration = (System.nanoTime() - startTime) / 1_000_000;
        recordMetric("generateOrderReport", duration);

        return new PaginatedReportResult(items, sanitizedPage, sanitizedSize, totalCount, duration);
    }

    public OrderSummaryDto getOrderById(String orderId) {
        if (orderId == null || !ORDER_CODE_PATTERN.matcher(orderId).matches()) {
            throw new IllegalArgumentException("Invalid order code format: " + orderId);
        }

        String sql = "SELECT order_id, customer_id, total_amount, status, created_at FROM orders WHERE order_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return mapRowToDto(rs);
                }
            }
        } catch (SQLException e) {
            logError("Failed to fetch order by ID", e);
            throw new RuntimeException("Database query failure", e);
        }
        return null;
    }

    public List<OrderSummaryDto> findRecentOrdersByCustomer(String customerId, int limit) {
        if (customerId == null || customerId.isBlank()) {
            return Collections.emptyList();
        }

        int queryLimit = Math.min(100, Math.max(1, limit));
        String sql = "SELECT order_id, customer_id, total_amount, status, created_at FROM orders WHERE customer_id = ? ORDER BY created_at DESC LIMIT ?";
        List<OrderSummaryDto> results = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, customerId);
            ps.setInt(2, queryLimit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    results.add(mapRowToDto(rs));
                }
            }
        } catch (SQLException e) {
            logError("Failed to query customer orders", e);
            throw new RuntimeException("Customer query failure", e);
        }
        return results;
    }

    public Map<String, Long> getOrderStatusAggregates(LocalDate fromDate) {
        String sql = "SELECT status, COUNT(*) AS count_val FROM orders WHERE created_at >= ? GROUP BY status";
        Map<String, Long> aggregates = new HashMap<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setDate(1, java.sql.Date.valueOf(fromDate != null ? fromDate : LocalDate.now().minusMonths(1)));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    aggregates.put(rs.getString("status"), rs.getLong("count_val"));
                }
            }
        } catch (SQLException e) {
            logError("Failed to compute aggregates", e);
            throw new RuntimeException("Aggregate computation failure", e);
        }
        return aggregates;
    }

    private long countMatchingOrders(ReportQueryCriteria criteria) {
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM orders WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (criteria.customerId() != null && !criteria.customerId().isBlank()) {
            sql.append(" AND customer_id = ?");
            params.add(criteria.customerId());
        }
        if (criteria.status() != null && !criteria.status().isBlank()) {
            sql.append(" AND status = ?");
            params.add(criteria.status());
        }
        if (criteria.startDate() != null) {
            sql.append(" AND created_at >= ?");
            params.add(java.sql.Date.valueOf(criteria.startDate()));
        }
        if (criteria.endDate() != null) {
            sql.append(" AND created_at <= ?");
            params.add(java.sql.Date.valueOf(criteria.endDate()));
        }

        try (PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                ps.setObject(i + 1, params.get(i));
            }
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        } catch (SQLException e) {
            logError("Count query failed", e);
            throw new RuntimeException("Count query failure", e);
        }
        return 0L;
    }

    private List<OrderSummaryDto> fetchOrderRows(
            ReportQueryCriteria criteria,
            int page,
            int size,
            String sortCol,
            String direction
    ) {
        StringBuilder sql = new StringBuilder("SELECT order_id, customer_id, total_amount, status, created_at FROM orders WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (criteria.customerId() != null && !criteria.customerId().isBlank()) {
            sql.append(" AND customer_id = ?");
            params.add(criteria.customerId());
        }
        if (criteria.status() != null && !criteria.status().isBlank()) {
            sql.append(" AND status = ?");
            params.add(criteria.status());
        }
        if (criteria.startDate() != null) {
            sql.append(" AND created_at >= ?");
            params.add(java.sql.Date.valueOf(criteria.startDate()));
        }
        if (criteria.endDate() != null) {
            sql.append(" AND created_at <= ?");
            params.add(java.sql.Date.valueOf(criteria.endDate()));
        }

        sql.append(" ORDER BY ").append(sortCol).append(" ").append(direction);
        sql.append(" LIMIT ? OFFSET ?");
        params.add(size);
        params.add(page * size);

        List<OrderSummaryDto> list = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                ps.setObject(i + 1, params.get(i));
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapRowToDto(rs));
                }
            }
        } catch (SQLException e) {
            logError("Fetch rows failed", e);
            throw new RuntimeException("Fetch rows failure", e);
        }
        return list;
    }

    private OrderSummaryDto mapRowToDto(ResultSet rs) throws SQLException {
        String orderId = rs.getString("order_id");
        String customerId = rs.getString("customer_id");
        double total = rs.getDouble("total_amount");
        String status = rs.getString("status");
        java.sql.Timestamp ts = rs.getTimestamp("created_at");
        Instant createdAt = ts != null ? ts.toInstant() : Instant.now();

        List<String> items = fetchOrderLineItems(orderId);
        return new OrderSummaryDto(orderId, customerId, total, status, createdAt, items);
    }

    private List<String> fetchOrderLineItems(String orderId) {
        String sql = "SELECT sku FROM order_line_items WHERE order_id = ?";
        List<String> skus = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    skus.add(rs.getString("sku"));
                }
            }
        } catch (SQLException e) {
            logWarning("Failed to fetch line items for order: " + orderId);
        }
        return skus;
    }

    private void validateCriteria(ReportQueryCriteria criteria) {
        if (criteria == null) {
            throw new IllegalArgumentException("Criteria cannot be null");
        }
        if (criteria.startDate() != null && criteria.endDate() != null && criteria.startDate().isAfter(criteria.endDate())) {
            throw new IllegalArgumentException("Start date cannot be after end date");
        }
        if (criteria.pageSize() > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("Page size exceeds maximum allowed of " + MAX_PAGE_SIZE);
        }
    }

    private void recordMetric(String operation, long durationMs) {
        executionMetrics.merge(operation, durationMs, (oldVal, newVal) -> (oldVal + newVal) / 2);
    }

    public Map<String, Long> getMetricsSnapshot() {
        return Collections.unmodifiableMap(executionMetrics);
    }

    public double calculateAverageOrderValue(String customerId) {
        String sql = "SELECT AVG(total_amount) AS avg_total FROM orders WHERE customer_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, customerId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getDouble("avg_total");
                }
            }
        } catch (SQLException e) {
            logError("Failed to calculate AOV", e);
        }
        return 0.0;
    }

    public boolean cancelPendingOrder(String orderId, String reason) {
        Objects.requireNonNull(orderId, "orderId required");
        Objects.requireNonNull(reason, "reason required");

        String updateSql = "UPDATE orders SET status = 'CANCELLED', cancellation_reason = ? WHERE order_id = ? AND status = 'PENDING'";
        try (PreparedStatement ps = connection.prepareStatement(updateSql)) {
            ps.setString(1, reason);
            ps.setString(2, orderId);
            int rows = ps.executeUpdate();
            return rows > 0;
        } catch (SQLException e) {
            logError("Failed to cancel order: " + orderId, e);
            return false;
        }
    }

    public List<String> listStaleOrders(int daysOld) {
        LocalDate cutoff = LocalDate.now().minusDays(Math.max(1, daysOld));
        String sql = "SELECT order_id FROM orders WHERE created_at < ? AND status = 'PENDING'";
        List<String> staleIds = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setDate(1, java.sql.Date.valueOf(cutoff));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    staleIds.add(rs.getString("order_id"));
                }
            }
        } catch (SQLException e) {
            logError("Failed to list stale orders", e);
        }
        return staleIds;
    }

    public void archiveOldOrders(LocalDate beforeDate) {
        String archiveSql = "INSERT INTO orders_archive SELECT * FROM orders WHERE created_at < ?";
        String deleteSql = "DELETE FROM orders WHERE created_at < ?";

        try {
            boolean originalAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try (PreparedStatement psArchive = connection.prepareStatement(archiveSql);
                 PreparedStatement psDelete = connection.prepareStatement(deleteSql)) {
                psArchive.setDate(1, java.sql.Date.valueOf(beforeDate));
                psArchive.executeUpdate();

                psDelete.setDate(1, java.sql.Date.valueOf(beforeDate));
                psDelete.executeUpdate();

                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(originalAutoCommit);
            }
        } catch (SQLException e) {
            logError("Failed to archive orders", e);
            throw new RuntimeException("Archive transaction failed", e);
        }
    }

    private void logError(String message, Throwable t) {
        System.err.printf(Locale.ROOT, "[ERROR] %s: %s%n", message, t.getMessage());
    }

    private void logWarning(String message) {
        System.out.printf(Locale.ROOT, "[WARN] %s%n", message);
    }
}
