package com.sentinelpr;

import com.sentinelpr.cli.SentinelCliRunner;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.DataflowTracker;
import com.sentinelpr.core.analysis.FrameworkContextAnalyzer;
import com.sentinelpr.core.analysis.SecretScanningEngine;
import com.sentinelpr.core.analysis.SuppressionManager;
import com.sentinelpr.core.service.AutomatedPatchService;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.PatchVerifier;
import com.sentinelpr.core.service.ReviewSessionMemory;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.core.service.SentinelAuditOrchestrator;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.nio.file.Path;

/**
 * <b>SentinelPrApplication</b>
 *
 * <p>Main Spring Boot application bootstrap for SentinelPR — Enterprise Code & Security Review Copilot.</p>
 */
@SpringBootApplication
public class SentinelPrApplication {

    public static void main(String[] args) {
        SpringApplication.run(SentinelPrApplication.class, args);
    }

    @Bean
    public SentinelClient sentinelClient() {
        return SentinelClient.getInstance();
    }

    @Bean
    public CodeInspectionService codeInspectionService(SentinelClient client) {
        return new CodeInspectionService(client);
    }

    @Bean
    public RuleEvaluationService ruleEvaluationService(SentinelClient client) {
        return new RuleEvaluationService(client);
    }

    @Bean
    public DataflowTracker dataflowTracker() {
        return new DataflowTracker();
    }

    @Bean
    public SecretScanningEngine secretScanningEngine() {
        return new SecretScanningEngine();
    }

    @Bean
    public FrameworkContextAnalyzer frameworkContextAnalyzer() {
        return new FrameworkContextAnalyzer();
    }

    @Bean
    public SuppressionManager suppressionManager() {
        return new SuppressionManager();
    }

    @Bean
    public PatchVerifier patchVerifier(CodeInspectionService inspectionService, RuleEvaluationService evaluationService) {
        return new PatchVerifier(inspectionService, evaluationService);
    }

    @Bean
    public PatchComposer patchComposer(SentinelClient client, PatchVerifier verifier) {
        return new PatchComposer(client.developer(), verifier);
    }

    @Bean
    public AutomatedPatchService automatedPatchService(SentinelClient client, PatchComposer composer, PatchVerifier verifier) {
        return new AutomatedPatchService(client, composer, verifier);
    }

    @Bean
    public ReviewSessionMemory reviewSessionMemory(SentinelClient client) {
        return new ReviewSessionMemory(client);
    }

    @Bean
    public SentinelAuditOrchestrator sentinelAuditOrchestrator(
            CodeInspectionService inspectionService,
            RuleEvaluationService evaluationService,
            AutomatedPatchService patchService,
            ReviewSessionMemory sessionMemory,
            SuppressionManager suppressionManager,
            DataflowTracker dataflowTracker
    ) {
        return new SentinelAuditOrchestrator(
                inspectionService,
                evaluationService,
                patchService,
                sessionMemory,
                suppressionManager,
                dataflowTracker
        );
    }

    @Bean
    public CommandLineRunner commandLineRunner(SentinelAuditOrchestrator orchestrator) {
        return args -> {
            if (args.length > 0 && !args[0].startsWith("--")) {
                Path target = Path.of(args[0]);
                SentinelCliRunner runner = new SentinelCliRunner(orchestrator);
                runner.run(target);
            }
        };
    }
}
