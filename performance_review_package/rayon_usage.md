# Rayon Parallelism Audit

Rayon is used for parallelizing sample-level validation runs:

## Execution Vector
* **Location**: `crates/cli/src/v2_validation.rs:1543`
* **Method**: `tasks.par_iter().map(...)`
* **Work Parallelized**: Each test case repository is treated as a fully independent task. Rayon schedules these tasks across a global thread pool.

## Bottlenecks & Tail Latency
1. **Global Mutex Serialization**: Access to the GitHub local file cache is synchronized via `CACHE_MUTEX` in `v2_validation.rs`. Threads checking the cache block sequentially, reducing CPU utility.
2. **Straggler Tasks**: Because the samples are sorted descending by size, the largest ones start first. However, the last few complex tasks taking 1,000,001 iterations run solo at the end, dropping CPU utilization to a single core (~12%).
