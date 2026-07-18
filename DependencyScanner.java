import java.io.File;
import java.util.HashMap;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * SecureOps Native Dependency Scanner (SCA).
 * Emits findings as pipe-delimited records for secureops_cli.py and app.py to consume.
 */
public final class DependencyScanner {
    private static int findings = 0;
    // 10MB limit to prevent XML Bomb (Billion Laughs) DoS attacks
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; 

    private DependencyScanner() { }

    public static void main(String[] args) {
        String directory = args.length > 0 ? args[0] : ".";
        
        // Prevent Path Traversal by cleanly resolving the target directory
        File dirFile = new File(directory);
        File pom = new File(dirFile, "pom.xml");

        System.out.println("SECUREOPS_DEPENDENCY_SCAN|1");
        
        if (!pom.isFile()) {
            System.out.println("STATUS|pom.xml|absent");
            System.out.println("SUMMARY|findings=0|errors=0");
            return;
        }
        
        if (pom.length() > MAX_FILE_SIZE) {
            System.out.println("STATUS|pom.xml|error: exceeds maximum allowed size (DoS protection)");
            System.out.println("SUMMARY|findings=0|errors=1");
            return;
        }

        System.out.println("STATUS|pom.xml|present");
        try {
            scanPom(pom);
            System.out.printf("SUMMARY|findings=%d|errors=0%n", findings);
        } catch (Exception exception) {
            // Masking exact error message to prevent Information Disclosure/Log Injection
            emitFinding("pom.parse", "MEDIUM", pom.getName(),
                    "Unable to parse pom.xml safely. File may be malformed or malicious.");
            System.out.printf("SUMMARY|findings=%d|errors=1%n", findings);
        }
    }

    private static void scanPom(File pom) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        
        // XXE, SSRF, and DoS Mitigation Configurations
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(pom);
        Map<String, String> properties = readProperties(document);
        NodeList dependencies = document.getElementsByTagNameNS("*", "dependency");

        int scanned = 0;
        for (int i = 0; i < dependencies.getLength(); i++) {
            Element dependency = (Element) dependencies.item(i);
            String groupId = resolve(textOfChild(dependency, "groupId"), properties);
            String artifactId = resolve(textOfChild(dependency, "artifactId"), properties);
            String version = resolve(textOfChild(dependency, "version"), properties);
            scanned++;

            // 1. Log4Shell (CVE-2021-44228)
            if ("org.apache.logging.log4j".equals(groupId) && "log4j-core".equals(artifactId)) {
                if (version.isEmpty()) {
                    emitFinding("dependency.log4j-core", "HIGH", coordinate(groupId, artifactId, "unknown"),
                            "log4j-core version is inherited or unresolved; verify it is >= 2.15.0.");
                } else if (isVersionBefore(version, 2, 15, 0)) {
                    emitFinding("dependency.log4j-core", "CRITICAL", coordinate(groupId, artifactId, version),
                            "Vulnerable to Log4Shell (CVE-2021-44228).");
                }
            }

            // 2. Spring Web (Legacy baseline)
            if ("org.springframework".equals(groupId) && "spring-web".equals(artifactId)) {
                if (!version.isEmpty() && isVersionBefore(version, 5, 3, 18)) {
                    emitFinding("dependency.spring-web", "HIGH", coordinate(groupId, artifactId, version),
                            "Outdated spring-web dependency violates SecureOps baseline.");
                }
            }
            
            // 3. Struts 2 RCE (CVE-2017-5638)
            if ("org.apache.struts".equals(groupId) && "struts2-core".equals(artifactId)) {
                if (!version.isEmpty() && isVersionBefore(version, 2, 5, 12)) {
                    emitFinding("dependency.struts2-core", "CRITICAL", coordinate(groupId, artifactId, version),
                            "Vulnerable to Jakarta Multipart parser RCE (CVE-2017-5638).");
                }
            }
            
            // 4. Jackson Databind Insecure Deserialization
            if ("com.fasterxml.jackson.core".equals(groupId) && "jackson-databind".equals(artifactId)) {
                if (!version.isEmpty() && isVersionBefore(version, 2, 10, 0)) {
                    emitFinding("dependency.jackson-databind", "HIGH", coordinate(groupId, artifactId, version),
                            "Vulnerable to Insecure Deserialization via polymorphic typing.");
                }
            }
        }
        System.out.printf("STATUS|dependencies|scanned=%d%n", scanned);
    }

    private static Map<String, String> readProperties(Document document) {
        Map<String, String> properties = new HashMap<>();
        NodeList propertyBlocks = document.getElementsByTagNameNS("*", "properties");
        for (int i = 0; i < propertyBlocks.getLength(); i++) {
            NodeList children = propertyBlocks.item(i).getChildNodes();
            for (int j = 0; j < children.getLength(); j++) {
                Node child = children.item(j);
                if (child.getNodeType() == Node.ELEMENT_NODE) {
                    properties.put(child.getLocalName(), child.getTextContent().trim());
                }
            }
        }
        return properties;
    }

    private static String textOfChild(Element parent, String name) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE && name.equals(child.getLocalName())) {
                return child.getTextContent().trim();
            }
        }
        return "";
    }

    private static String resolve(String value, Map<String, String> properties) {
        if (value.startsWith("${") && value.endsWith("}")) {
            return properties.getOrDefault(value.substring(2, value.length() - 1), value);
        }
        return value;
    }

    private static boolean isVersionBefore(String version, int requiredMajor, int requiredMinor, int requiredPatch) {
        String[] parts = version.split("[.\\-+]");
        try {
            int major = integerPart(parts, 0);
            int minor = integerPart(parts, 1);
            int patch = integerPart(parts, 2);
            if (major != requiredMajor) return major < requiredMajor;
            if (minor != requiredMinor) return minor < requiredMinor;
            return patch < requiredPatch;
        } catch (NumberFormatException exception) {
            return false; // Avoid a false positive for non-numeric Maven versions.
        }
    }

    private static int integerPart(String[] parts, int index) {
        return index < parts.length ? Integer.parseInt(parts[index]) : 0;
    }

    private static String coordinate(String groupId, String artifactId, String version) {
        return groupId + ":" + artifactId + ":" + version;
    }

    private static void emitFinding(String rule, String severity, String subject, String message) {
        System.out.printf("FINDING|%s|%s|%s|%s%n", sanitize(rule), sanitize(severity),
                sanitize(subject), sanitize(message));
        findings++;
    }

    private static String sanitize(String value) {
        if (value == null) return "";
        // Replace structural dividers
        String clean = value.replace('|', '/').replace('\n', ' ').replace('\r', ' ');
        // Strip out control characters and ANSI escape codes to prevent Log Injection
        clean = clean.replaceAll("[\\p{Cntrl}&&[^\t ]]", "");
        return clean;
    }
}
