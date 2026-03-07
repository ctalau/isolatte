# Research Plan: JRE Class Dependencies

**Goal:** Identify which built-in JRE classes (java.*, javax.*, sun.*, com.sun.*) are used by dita-ot and all its transitive dependencies.

**Method:** Analyze source code imports in each project's GitHub repository. Each project gets a file under `research/` listing the JRE packages/classes it uses.

## Status Legend
- [ ] Not started
- [x] Done

---

## Phase 1: dita-ot (core)

- [ ] Research dita-ot JRE class usage → `research/dita-ot.txt`

## Phase 2: Direct Dependencies of dita-ot

From `build.gradle`:
- [ ] commons-io:2.19.0 → `research/commons-io.txt`
- [ ] xerces:xercesImpl:2.12.2 → `research/xerces.txt`
- [ ] xml-apis:1.4.01 → `research/xml-apis.txt`
- [ ] xml-resolver:1.2 → `research/xml-resolver.txt`
- [ ] Saxon-HE:12.9 → `research/saxon-he.txt`
- [ ] xmlresolver:5.3.3 → `research/xmlresolver.txt`
- [ ] icu4j:77.1 → `research/icu4j.txt`
- [ ] ant:1.10.15 → `research/ant.txt`
- [ ] ant-launcher:1.10.15 → `research/ant-launcher.txt`
- [ ] guava:33.4.8-jre → `research/guava.txt`
- [ ] slf4j-api:2.0.17 → `research/slf4j-api.txt`
- [ ] logback-classic:1.5.19 → `research/logback-classic.txt`
- [ ] jackson-core:2.19.0 → `research/jackson-core.txt`
- [ ] jackson-databind:2.19.0 → `research/jackson-databind.txt`
- [ ] jackson-dataformat-yaml:2.19.0 → `research/jackson-dataformat-yaml.txt`
- [ ] jing:20241231 → `research/jing.txt`
- [ ] ant-apache-resolver:1.10.15 → `research/ant-apache-resolver.txt`

## Phase 3: Transitive Dependencies

Each dependency's own dependencies will be tracked recursively. New entries will be added here as discovered.

### logback-classic dependencies
- [ ] logback-core → `research/logback-core.txt`

### jackson-dataformat-yaml dependencies
- [ ] snakeyaml → `research/snakeyaml.txt`

### xmlresolver dependencies
- [ ] data-uri → TBD

*(More will be added as research progresses)*

---

## Notes
- Focus on JRE built-in packages: `java.*`, `javax.*`, `sun.*`, `com.sun.*`, `jdk.*`, `org.w3c.*`, `org.xml.*`
- Source code analyzed via GitHub repositories
