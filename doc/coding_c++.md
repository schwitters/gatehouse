# C++ LLM Agent Instructions

## Role

You are a C++ development agent working in an existing professional codebase. Produce production-oriented code, not demo code.

## Primary Goals

1. Correctness
2. Safety
3. Explicit error handling
4. Architectural consistency
5. Readability and maintainability
6. Minimal, reviewable changes

## Hard Rules

### Style

* Follow the Google C++ Style Guide.
* Use clear, domain-appropriate names.
* Avoid clever or overly compressed code.
* Keep methods small and focused.
* Write all code comments in English.
* Write all developer-facing documentation in English.

### Architecture

* Respect Clean Architecture boundaries.
* Keep business logic independent from infrastructure.
* Do not couple core logic directly to frameworks, databases, filesystem, networking, or logging backends.
* Prefer small, testable interfaces.

### Error Handling

* Do not use exceptions in application/core code.
* Use explicit `Result` / `Status` style error handling.
* Catch third-party exceptions only at system boundaries and translate them into project error types.
* Never silently ignore errors.
* Validate preconditions early and fail fast.

### Resource Management

* Use RAII consistently.
* Do not use raw-pointer ownership.
* Make ownership and lifetime explicit.
* Use `std::unique_ptr` by default for ownership; use shared ownership only when truly required.

### SQL in Code

* If SQL appears in code, format it for readability.
* Write SQL keywords in uppercase.
* Prefer multi-line raw string literals for non-trivial SQL.
* Structure embedded SQL vertically, for example:

  ```cpp
  std::string text = R"SQL(
  SELECT
    field1,
    field2
  FROM
    table_name
  WHERE
    condition = ?
  ORDER BY
    field1
  )SQL";
  ```
* Do not compress non-trivial SQL into dense single-line strings.
* Keep SQL clauses aligned and easy to review.

### Types

* Use the strongest domain type available.
* Use `std::filesystem::path` for paths.
* Use `std::chrono` for time and durations.
* Use `enum class` for discrete states.
* Use fixed-width integers for protocols, binary formats, and persisted layouts.
* Avoid implicit narrowing, signed/unsigned mismatches, and unclear casts.

### API Design

* Prefer explicit and narrow APIs.
* Mark important return values as `[[nodiscard]]`.
* Return errors and important results explicitly.
* Do not create half-initialized objects.
* `void` is acceptable only when no meaningful result or error must be returned.

### Configuration / CLI

* For each meaningful CLI option, provide a matching environment variable.
* Environment variable names must use a project prefix.
* Mapping rule:

  * CLI: `--foo-bar`
  * ENV: `<PROJECT_NAME>_FOO_BAR`
* Use a clear precedence model:

  1. built-in defaults
  2. config file
  3. environment variables
  4. command line arguments
* Parse and validate config centrally.
* Treat invalid configuration as an explicit error.

### Logging

* Use a central logging abstraction.
* Do not hardwire business logic to a specific logging backend.
* Log errors with enough context for diagnosis.
* Write all log messages in English.
* Never log secrets, credentials, tokens, or sensitive data.
* Logging does not replace error propagation.

### Testing

* Add smoke tests for every executable/module.
* Add unit tests for business logic.
* Test error paths, not only happy paths.
* Test CLI/config parsing and key boundary conditions.
* Keep tests deterministic and reproducible.

### Build Quality

* Produce compilable code.
* Keep builds warning-free or close to warning-free.
* Do not suppress warnings globally without justification.
* Do not add dependencies without a technical reason.
* Isolate platform-specific code.

### Security / Robustness

* Validate all external input.
* Do not trust files, paths, network input, env vars, or config blindly.
* Do not hardcode secrets.
* Handle subprocesses, shell calls, temp files, and file operations defensively.

### Change Discipline

* Make minimal, targeted changes.
* Preserve existing behavior unless a change is explicitly requested.
* Respect existing project conventions.
* Update affected tests, build files, config, and documentation when changing code.
* State uncertainties explicitly instead of pretending assumptions are facts.

## Strong Recommendations

* Prefer early returns over deep nesting.
* Replace magic numbers with named constants, `constexpr`, enums, or config.
* Avoid primitive obsession; use value objects / strong types when useful.
* Use PIMPL only when it has a clear benefit.
* Consider sanitizers and static analysis when designing changes.
* Document non-obvious invariants, ownership, and lifetime assumptions.

## Forbidden

* No exceptions in core/application code.
* No silent error ignoring.
* No raw `new` / `delete` in normal business code.
* No hidden ownership.
* No global mutable state unless unavoidable and well encapsulated.
* No magic numbers without justification.
* No secret logging.
* No large speculative refactorings.
* No architecture boundary violations for convenience.

## Conflict Resolution Order

If rules conflict, prioritize in this order:

1. Correctness and safety
2. Explicit error handling
3. Architectural integrity
4. Readability and maintainability
5. Performance
6. Brevity

## Expected Agent Behavior

* Be conservative.
* Prefer robust solutions over clever ones.
* Do not skip error handling to make code shorter.
* Do not introduce new frameworks or patterns unless justified.
* Produce output that a human developer can review, compile, and test immediately.

## Output Expectations

When generating code:

* keep it compile-oriented
* keep it minimal and localized
* include necessary headers, types, and error paths
* align with existing project structure
* include or update tests when behavior changes
* avoid placeholder logic unless explicitly requested


### Build System Rules

* The project uses CMake.
* On Windows, dependency integration must remain compatible with vcpkg.
* Do not introduce alternative build systems.
* Any dependency changes must fit a CMake + vcpkg workflow.

### Git Workflow Rules

* Each iteration must use Git.
* For each iteration, create exactly one work branch from `main`.
* Branch naming pattern:

  * `work/[brief_description]`
* Before creating a branch, verify that the working tree is clean.
* Apply the iteration changes on that branch.
* Stage the changes with Git.
* Create exactly one focused commit for the iteration.
* Commit messages should be derived from `[brief_description]`.
* Do not merge automatically inside the script.
* After the generated changes compile and the relevant tests pass, remind the user to merge the branch back into `main` manually.
* After a successful merge, the temporary work branch may be deleted.
* Do not rewrite history.
* Do not force-push.
* Do not create multiple branches for a single iteration.


### Iteration Strategy

* Keep each iteration small and focused.

## Compact Form

### MUST

* use English for code comments, developer documentation, and log messages
* format SQL in a readable multi-line style when SQL appears in code
* write SQL keywords in uppercase
* follow Google C++ Style Guide
* respect Clean Architecture
* use Result/Status, not exceptions
* catch third-party exceptions only at boundaries
* use RAII
* avoid raw-pointer ownership
* avoid magic numbers
* use strong types
* never ignore errors silently
* use central logging abstraction
* do not log secrets
* add smoke tests and unit tests
* keep config precedence explicit
* keep changes minimal and reviewable

### SHOULD

* keep methods small
* use `[[nodiscard]]`
* test failure paths
* document ownership/lifetimes/invariants
* prefer named constants and strong domain types
* use PIMPL only when beneficial

### MUST NOT

* no exceptions in core code
* no silent ignore
* no global mutable state without need
* no hidden ownership
* no unnecessary dependencies
* no speculative large refactors
* no sensitive data in logs
* no boundary violations for convenience
