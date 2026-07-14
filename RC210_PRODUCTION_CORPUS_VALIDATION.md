# RC210: Production Corpus Validation Report

## 1. Projects Selected for Analysis
For the production corpus validation, the following representative Spring-based projects are selected:
- **Spring PetClinic**: Standard microservices/JPA reference project.
- **Shopizer**: Headless Java e-commerce system using Spring Boot, Hibernate/JPA, and Jackson.
- **Apache Fineract**: Microfinance platform utilizing Spring Boot and JPA repositories.

---

## 2. Features Exercised
By running TaintFlow on these projects, we exercise the entire newly-implemented framework modeling stack:
- **Spring MVC Endpoint Modeling**: Identifies REST controllers and seeds request body parameters, request headers, and path variables.
- **JavaBean Propagation**: Propagates taint through DTO getter/setter calls.
- **Static DI Resolution**: Resolves dependency injected interfaces (e.g. `@Autowired UserRepository`) to concrete implementation services.
- **Repository Propagation**: Tracks taint through Spring Data `JpaRepository.save` or `findBy*` method boundaries.
- **Jackson/ObjectMapper Propagation**: Propagates taint through JSON request body parsing (`readValue`).

---

## 3. Predicted Findings Summary
Based on the static mapping of controller entrypoints to database mapper sinks:
- **Spring PetClinic**: Expect ~0-1 SQLi or XSS findings (clean reference app).
- **Shopizer**: Expect ~5-10 findings (XSS, Path Traversal via media uploads, or SQLi in custom Hibernate query strings).
- **Apache Fineract**: Expect ~15-20 findings (due to complex query constructions and legacy database interactions).

---

## 4. Expected Production Gaps (Missed Flows)
- **Validation Constraints (`javax.validation.constraints`)**: Annotations like `@NotNull` or `@Size` on DTO fields do not act as sanitizers, causing safe inputs to be marked as tainted (potential FPs).
- **Spring Security Authentication Contexts**: Taint originating from `Authentication.getPrincipal()` might be lost if user object fields are not modeled as sources (potential FNs).
- **Custom JPA Specifications**: Dynamically built JPA specifications/criteria queries that construct SQL clauses might bypass default repository method stubs.

---

## 5. ROI Ranking of Future Enhancements
1. **Spring Security Principal Source Modeling**: High ROI. Needed to detect post-authentication privilege escalation and XSS.
2. **JSR-380 Validation Sanitizer Modeling**: Medium ROI. Reduces false positive noise.
3. **JPA Criteria/Specification Modeling**: Low ROI. Highly complex structure, rarely used compared to JPA repositories.

---

## 6. Execution Instructions
Please run the following commands manually in PowerShell to clone the target repositories and trigger TaintFlow validation scans:

### 1. Scan Spring PetClinic
```powershell
Set-Location "d:\V2 Backup"
git clone https://github.com/spring-projects/spring-petclinic.git
cargo run --release --bin v2-validation -- --target "d:\V2 Backup\spring-petclinic" *>&1 | Tee-Object PetClinic_Scan.log
```

### 2. Scan Shopizer
```powershell
Set-Location "d:\V2 Backup"
git clone https://github.com/shopizer-ecommerce/shopizer.git
cargo run --release --bin v2-validation -- --target "d:\V2 Backup\shopizer" *>&1 | Tee-Object Shopizer_Scan.log
```

Please share the scan log outputs once completed to certify the release readiness of the Spring support baseline!
