package com.sentinelpr.fixture;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * <b>EnterpriseSecurityVulnerableService</b>
 *
 * <p>Test fixture demonstrating P1 enterprise security vulnerabilities:</p>
 * <ol>
 *   <li>SEC-005-SQL-INJECTION: Raw string concatenation in SQL execution sink</li>
 *   <li>SEC-006-PATH-TRAVERSAL: Unvalidated file/path instantiation with user input</li>
 *   <li>SEC-007-INSECURE-DESERIALIZATION: Unfiltered ObjectInputStream.readObject()</li>
 *   <li>SEC-008-HARDCODED-SECRET: High-entropy AWS access key token</li>
 *   <li>SEC-010-SPRING-PERMISSIVE-CORS: Permissive wildcard CORS origin</li>
 *   <li>Suppressed variations for false-positive suppression validation</li>
 * </ol>
 */
@RestController
@CrossOrigin(origins = "*")
public class EnterpriseSecurityVulnerableService {

    // SEC-008: Hardcoded high-entropy AWS Access Key ID
    private static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";

    /**
     * SEC-005: Raw concatenated SQL query passed to Statement.executeQuery
     */
    public ResultSet queryUserData(Connection conn, String username) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }

    /**
     * SEC-005 Suppressed: SQL query with @SuppressWarnings("sentinel:SEC-005")
     */
    @SuppressWarnings("sentinel:SEC-005")
    public ResultSet queryUserDataSuppressed(Connection conn, String internalRole) throws SQLException {
        String query = "SELECT * FROM roles WHERE name = '" + internalRole + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }

    /**
     * SEC-006: Path traversal in File construction without containment check
     */
    public File loadUserReport(File baseDir, String reportName) {
        File reportFile = new File(baseDir, reportName);
        return reportFile;
    }

    /**
     * SEC-006 Suppressed: Path traversal suppressed via inline comment
     */
    public File loadSystemAsset(File baseDir, String assetName) {
        // sentinel-ignore SEC-006 Asset name validated by caller security filter
        File assetFile = new File(baseDir, assetName);
        return assetFile;
    }

    /**
     * SEC-007: Insecure ObjectInputStream deserialization without ObjectInputFilter
     */
    public Object deserializeUntrusted(byte[] rawData) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(rawData))) {
            return ois.readObject();
        }
    }

    /**
     * Safe baseline: Method using Path.normalize() and boundary check (should NOT trigger SEC-006)
     */
    public Path loadSecuredDocument(Path basePath, String documentPath) {
        Path target = Path.of(basePath.toString(), documentPath).normalize();
        if (!target.startsWith(basePath.normalize())) {
            throw new SecurityException("Path traversal attempt detected");
        }
        return target;
    }

    public String getAwsAccessKeyId() {
        return AWS_ACCESS_KEY_ID;
    }
}
