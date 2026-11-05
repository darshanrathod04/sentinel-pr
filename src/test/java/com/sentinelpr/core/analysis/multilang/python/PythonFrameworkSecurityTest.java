package com.sentinelpr.core.analysis.multilang.python;

import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.RuleEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Phase 5: Python Framework-Specific Security Intelligence Test Suite")
public class PythonFrameworkSecurityTest {

    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;

    @BeforeEach
    void setUp() {
        this.inspectionService = new CodeInspectionService();
        this.evaluationService = new RuleEvaluationService();
    }

    @Test
    @DisplayName("Flask: Detect dynamic render_template_string SSTI/XSS and Markup()")
    void testFlaskSecurityRules() {
        String vulnFlask = """
                from flask import Flask, request, render_template_string, Markup
                app = Flask(__name__)

                @app.route("/hello")
                def hello():
                    name = request.args.get("name", "World")
                    template = f"<h1>Hello {name}</h1>"
                    return render_template_string(template)

                @app.route("/raw")
                def raw_html():
                    user_bio = request.args.get("bio")
                    return Markup(user_bio)
                """;

        InspectedSource source = inspectionService.inspectSourceCode(vulnFlask, "flask_app.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        long xssCount = findings.stream().filter(f -> f.getRule() == SecurityRule.XSS).count();
        assertTrue(xssCount >= 2, "Must flag both render_template_string and Markup with dynamic content");

        String safeFlask = """
                from flask import Flask, render_template
                app = Flask(__name__)

                @app.route("/hello")
                def hello_safe():
                    return render_template("hello.html", name="guest")
                """;

        InspectedSource safeSource = inspectionService.inspectSourceCode(safeFlask, "flask_safe.py");
        List<SecurityFinding> safeFindings = evaluationService.evaluate(safeSource);
        assertFalse(safeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.XSS),
                "Static render_template must not be flagged");
    }

    @Test
    @DisplayName("Flask: Detect debug mode enabled in configuration")
    void testFlaskDebugMode() {
        String vulnConfig = """
                from flask import Flask
                app = Flask(__name__)
                app.config['DEBUG'] = True
                """;

        InspectedSource source = inspectionService.inspectSourceCode(vulnConfig, "config.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.FAIL_OPEN_SECURITY),
                "Must flag Flask DEBUG = True");
    }

    @Test
    @DisplayName("Django: Detect mark_safe XSS and Model.objects.raw() SQLi")
    void testDjangoViewSecurity() {
        String vulnDjango = """
                from django.utils.safestring import mark_safe
                from myapp.models import User

                def profile_view(request):
                    bio = request.GET.get("bio")
                    safe_bio = mark_safe(bio)
                    
                    user_id = request.GET.get("id")
                    users = User.objects.raw("SELECT * FROM users WHERE id = " + user_id)
                    return users
                """;

        InspectedSource source = inspectionService.inspectSourceCode(vulnDjango, "views.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.XSS),
                "Must flag mark_safe() with dynamic argument");
        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.SQL_INJECTION),
                "Must flag Model.objects.raw() with string concatenation");
    }

    @Test
    @DisplayName("Django: Detect wildcard ALLOWED_HOSTS and DEBUG=True in settings")
    void testDjangoSettings() {
        String vulnSettings = """
                DEBUG = True
                ALLOWED_HOSTS = ['*']
                SECRET_KEY = 'django-insecure-test'
                """;

        InspectedSource source = inspectionService.inspectSourceCode(vulnSettings, "settings.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        long configBypasses = findings.stream().filter(f -> f.getRule() == SecurityRule.FAIL_OPEN_SECURITY).count();
        assertTrue(configBypasses >= 2, "Must flag both DEBUG=True and ALLOWED_HOSTS=['*'] in settings.py");
    }

    @Test
    @DisplayName("FastAPI: Detect permissive CORS middleware with credentials")
    void testFastApiCorsSecurity() {
        String vulnFastApi = """
                from fastapi import FastAPI
                from fastapi.middleware.cors import CORSMiddleware

                app = FastAPI()
                app.add_middleware(
                    CORSMiddleware,
                    allow_origins=["*"],
                    allow_credentials=True,
                    allow_methods=["*"],
                    allow_headers=["*"],
                )
                """;

        InspectedSource source = inspectionService.inspectSourceCode(vulnFastApi, "main.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.SPRING_PERMISSIVE_CORS),
                "Must flag wildcard origins with allow_credentials=True in FastAPI");

        String safeFastApi = """
                from fastapi import FastAPI
                from fastapi.middleware.cors import CORSMiddleware

                app = FastAPI()
                app.add_middleware(
                    CORSMiddleware,
                    allow_origins=["https://app.example.com"],
                    allow_credentials=True,
                )
                """;

        InspectedSource safeSource = inspectionService.inspectSourceCode(safeFastApi, "main_safe.py");
        List<SecurityFinding> safeFindings = evaluationService.evaluate(safeSource);
        assertFalse(safeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.SPRING_PERMISSIVE_CORS),
                "Explicit allow_origins must not be flagged");
    }
}
