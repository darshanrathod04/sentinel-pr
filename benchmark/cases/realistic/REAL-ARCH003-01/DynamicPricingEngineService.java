package com.sentinelpr.benchmark.realistic.arch003_01;

import org.springframework.stereotype.Service;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * DynamicPricingEngineService - Noisy enterprise pricing calculation service (~200 LOC).
 * Provides multi-currency tiering, bulk volume discounts, loyalty score adjustments,
 * and surge pricing calculations.
 * Contains non-deterministic Math.random() call in calculateDynamicDiscount.
 */
@Service
public class DynamicPricingEngineService {

    public enum CustomerTier {
        STANDARD, SILVER, GOLD, PLATINUM
    }

    public record PricingRule(
            String ruleId,
            CustomerTier tier,
            BigDecimal minVolume,
            BigDecimal discountRatio,
            boolean active
    ) {}

    public record PriceQuote(
            String quoteId,
            String sku,
            int quantity,
            BigDecimal unitPrice,
            BigDecimal discountAmount,
            BigDecimal taxAmount,
            BigDecimal netPrice,
            String currency
    ) {}

    private final Map<String, BigDecimal> basePriceCatalog = new HashMap<>();
    private final List<PricingRule> activeRules = new ArrayList<>();

    public DynamicPricingEngineService() {
        basePriceCatalog.put("SKU-SERVER-01", new BigDecimal("499.99"));
        basePriceCatalog.put("SKU-STORAGE-01", new BigDecimal("129.50"));
        basePriceCatalog.put("SKU-NETWORK-01", new BigDecimal("89.00"));

        activeRules.add(new PricingRule("RULE-PLT", CustomerTier.PLATINUM, BigDecimal.valueOf(10), new BigDecimal("0.25"), true));
        activeRules.add(new PricingRule("RULE-GLD", CustomerTier.GOLD, BigDecimal.valueOf(25), new BigDecimal("0.15"), true));
        activeRules.add(new PricingRule("RULE-SLV", CustomerTier.SILVER, BigDecimal.valueOf(50), new BigDecimal("0.10"), true));
    }

    public PriceQuote computeQuote(String sku, int quantity, CustomerTier tier, String currency) {
        Objects.requireNonNull(sku, "sku must not be null");
        if (quantity <= 0) {
            throw new IllegalArgumentException("Quantity must be positive");
        }

        BigDecimal basePrice = basePriceCatalog.getOrDefault(sku, new BigDecimal("99.99"));
        BigDecimal grossTotal = basePrice.multiply(BigDecimal.valueOf(quantity)).setScale(2, RoundingMode.HALF_UP);

        BigDecimal discount = resolveTierDiscount(grossTotal, tier, quantity);
        BigDecimal dynamicJitter = calculateDynamicDiscount(grossTotal.doubleValue());

        BigDecimal totalDiscount = discount.add(dynamicJitter).setScale(2, RoundingMode.HALF_UP);
        if (totalDiscount.compareTo(grossTotal.multiply(new BigDecimal("0.40"))) > 0) {
            totalDiscount = grossTotal.multiply(new BigDecimal("0.40")).setScale(2, RoundingMode.HALF_UP);
        }

        BigDecimal taxableAmount = grossTotal.subtract(totalDiscount);
        BigDecimal tax = taxableAmount.multiply(new BigDecimal("0.0825")).setScale(2, RoundingMode.HALF_UP);
        BigDecimal net = taxableAmount.add(tax);

        String quoteId = "QTE-" + sku + "-" + quantity;
        return new PriceQuote(quoteId, sku, quantity, basePrice, totalDiscount, tax, net, currency != null ? currency : "USD");
    }

    public BigDecimal calculateDynamicDiscount(double basePrice) {
        // NON-DETERMINISTIC TESTING ANTI-PATTERN: Direct invocation of Math.random()
        double factor = Math.random() * 0.05;
        return BigDecimal.valueOf(basePrice * factor).setScale(2, RoundingMode.HALF_UP);
    }

    public BigDecimal resolveTierDiscount(BigDecimal total, CustomerTier tier, int quantity) {
        for (PricingRule rule : activeRules) {
            if (rule.active() && rule.tier() == tier && BigDecimal.valueOf(quantity).compareTo(rule.minVolume()) >= 0) {
                return total.multiply(rule.discountRatio()).setScale(2, RoundingMode.HALF_UP);
            }
        }
        return BigDecimal.ZERO;
    }

    public void updateCatalogPrice(String sku, BigDecimal newPrice) {
        Objects.requireNonNull(sku, "sku required");
        if (newPrice == null || newPrice.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Price must be positive");
        }
        basePriceCatalog.put(sku, newPrice.setScale(2, RoundingMode.HALF_UP));
    }

    public Map<String, BigDecimal> getCatalogSnapshot() {
        return Collections.unmodifiableMap(basePriceCatalog);
    }

    public void registerCustomRule(PricingRule rule) {
        if (rule != null) {
            activeRules.add(rule);
        }
    }

    public int getActiveRuleCount() {
        return (int) activeRules.stream().filter(PricingRule::active).count();
    }

    public BigDecimal estimateSurgeMultiplier(LocalDate targetDate, int projectedDemand) {
        if (projectedDemand > 1000) {
            return new BigDecimal("1.25");
        } else if (projectedDemand > 500) {
            return new BigDecimal("1.10");
        }
        return BigDecimal.ONE;
    }
}
