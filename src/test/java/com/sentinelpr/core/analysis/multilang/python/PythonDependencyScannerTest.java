package com.sentinelpr.core.analysis.multilang.python;

import com.sentinelpr.core.analysis.multilang.python.deps.PythonDependencyScanner;
import com.sentinelpr.core.model.SecurityFinding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Phase 5: Python Dependency & Config Security Scanner Test Suite")
public class PythonDependencyScannerTest {

    private PythonDependencyScanner scanner;

    @BeforeEach
    void setUp() {
        this.scanner = new PythonDependencyScanner();
    }

    @Test
    @DisplayName("requirements.txt: Flag known vulnerable pinned packages")
    void testRequirementsTxtScanning() {
        String reqs = """
                # Production Dependencies
                requests==2.25.1
                urllib3==1.26.5
                pyyaml==5.3.1
                gunicorn==20.1.0
                """;

        List<SecurityFinding> findings = scanner.scanContent(reqs, "requirements.txt", "requirements.txt");
        assertEquals(3, findings.size(), "Must detect vulnerable requests, urllib3, and pyyaml");

        assertTrue(findings.stream().anyMatch(f -> f.getDescription().contains("requests") && f.getDescription().contains("CVE-2023-32681")));
        assertTrue(findings.stream().anyMatch(f -> f.getDescription().contains("urllib3") && f.getDescription().contains("CVE-2023-45803")));
        assertTrue(findings.stream().anyMatch(f -> f.getDescription().contains("pyyaml") && f.getDescription().contains("CVE-2020-14343")));
    }

    @Test
    @DisplayName("pyproject.toml: Flag vulnerable dependencies in poetry and standard config")
    void testPyProjectTomlScanning() {
        String toml = """
                [project]
                name = "my-app"
                dependencies = [
                    "django = 4.2.0",
                    "cryptography = 41.0.1"
                ]
                """;

        List<SecurityFinding> findings = scanner.scanContent(toml, "pyproject.toml", "pyproject.toml");
        assertEquals(2, findings.size(), "Must detect vulnerable django and cryptography in pyproject.toml");
        assertTrue(findings.stream().anyMatch(f -> f.getDescription().contains("django") && f.getDescription().contains("CVE-2024-24680")));
    }

    @Test
    @DisplayName("poetry.lock: Detect vulnerable packages from lockfile entries")
    void testPoetryLockScanning() {
        String lock = """
                [[package]]
                name = "pillow"
                version = "9.5.0"
                description = "Python Imaging Library"

                [[package]]
                name = "paramiko"
                version = "2.9.2"
                description = "SSH2 protocol library"
                """;

        List<SecurityFinding> findings = scanner.scanContent(lock, "poetry.lock", "poetry.lock");
        assertEquals(2, findings.size(), "Must detect vulnerable pillow and paramiko in poetry.lock");
    }

    @Test
    @DisplayName("Pipfile: Detect vulnerable packages in Pipfile format")
    void testPipfileScanning() {
        String pipfile = """
                [[source]]
                url = "https://pypi.org/simple"

                [packages]
                sqlparse = "==0.4.1"
                requests = "==2.28.0"
                """;

        List<SecurityFinding> findings = scanner.scanContent(pipfile, "Pipfile", "Pipfile");
        assertEquals(2, findings.size(), "Must detect vulnerable sqlparse and requests in Pipfile");
    }

    @Test
    @DisplayName("Up-to-date dependencies: Produce zero false positive findings")
    void testSafeDependencies() {
        String safeReqs = """
                requests==2.31.0
                urllib3==1.26.18
                django==4.2.10
                pyyaml==6.0.1
                cryptography==42.0.0
                pillow==10.1.0
                """;

        List<SecurityFinding> findings = scanner.scanContent(safeReqs, "requirements.txt", "requirements.txt");
        assertTrue(findings.isEmpty(), "Patched and up-to-date versions must produce 0 findings");
    }
}
